#![no_std]
#![forbid(unsafe_code)]
#![doc = "Input event management for JustRDP."]
#![doc = ""]
#![doc = "Tracks keyboard and mouse state, generates diff-based input events."]

// ══════════════════════════════════════════════════════════════
// Scancode
// ══════════════════════════════════════════════════════════════

/// A keyboard scancode with an extended flag.
///
/// - Slow-path: MS-RDPBCGR §2.2.8.1.1.3.1.1.1 (TS_KEYBOARD_EVENT)
/// - Fast-path: MS-RDPBCGR §2.2.8.1.2.2.1 (TS_FP_KEYBOARD_EVENT)
///
/// The 8-bit scancode + extended bit covers the full PC/AT keyboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Scancode {
    /// 8-bit scancode value.
    pub code: u8,
    /// Whether the extended (E0) prefix is set.
    pub extended: bool,
}

impl Scancode {
    /// Create a new scancode.
    pub const fn new(code: u8, extended: bool) -> Self {
        Self { code, extended }
    }

    /// Convert to a 9-bit index (0–511) for bitfield storage.
    #[inline]
    #[must_use]
    pub const fn index(self) -> usize {
        (self.code as usize) | if self.extended { 256 } else { 0 }
    }

    /// Create from a 9-bit index. `index` must be in `0..512`.
    ///
    /// # Panics
    ///
    /// Panics if `index >= 512`.
    #[must_use]
    pub fn from_index(index: usize) -> Self {
        assert!(index < 512, "Scancode index out of range: {index}");
        Self {
            code: (index & 0xFF) as u8,
            extended: index & 256 != 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// Mouse button
// ══════════════════════════════════════════════════════════════

/// Mouse button identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
    X1,
    X2,
}

impl MouseButton {
    /// Convert to a bit index (0–4).
    #[inline]
    const fn index(self) -> usize {
        match self {
            Self::Left => 0,
            Self::Right => 1,
            Self::Middle => 2,
            Self::X1 => 3,
            Self::X2 => 4,
        }
    }

    /// All button variants for iteration.
    pub const ALL: [MouseButton; 5] = [
        Self::Left,
        Self::Right,
        Self::Middle,
        Self::X1,
        Self::X2,
    ];
}

// ══════════════════════════════════════════════════════════════
// Operation (input event)
// ══════════════════════════════════════════════════════════════

/// An input operation generated from state diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    KeyPressed(Scancode),
    KeyReleased(Scancode),
    UnicodeKeyPressed(u16),
    UnicodeKeyReleased(u16),
    MouseButtonPressed(MouseButton),
    MouseButtonReleased(MouseButton),
    /// Absolute mouse move to (x, y).
    MouseMove { x: u16, y: u16 },
    /// Relative mouse movement — MS-RDPBCGR §2.2.8.1.1.3.1.1.3.
    RelativeMouseMove { dx: i16, dy: i16 },
    /// Vertical wheel rotation (positive = up).
    WheelRotations(i16),
    /// Horizontal wheel rotation (positive = right).
    HorizontalWheelRotations(i16),
    /// Lock key synchronization event (MS-RDPBCGR §2.2.8.1.1.3.1.1.5).
    SynchronizeEvent(LockKeys),
}

impl Operation {
    /// Create a wheel rotation operation. Stateless — always produces an event.
    #[must_use]
    pub fn wheel_rotations(delta: i16) -> Self {
        Self::WheelRotations(delta)
    }

    /// Create a horizontal wheel rotation operation. Stateless — always produces an event.
    #[must_use]
    pub fn horizontal_wheel_rotations(delta: i16) -> Self {
        Self::HorizontalWheelRotations(delta)
    }

    /// Create a relative mouse move operation. Stateless — always produces an event.
    #[must_use]
    pub fn relative_mouse_move(dx: i16, dy: i16) -> Self {
        Self::RelativeMouseMove { dx, dy }
    }
}

// ══════════════════════════════════════════════════════════════
// Lock key flags (for synchronize_event)
// ══════════════════════════════════════════════════════════════

/// Lock key state flags.
///
/// - Slow-path: MS-RDPBCGR §2.2.1.14 (Synchronize PDU)
/// - Fast-path: MS-RDPBCGR §2.2.8.1.1.3.1.1.5 (TS_FP_SYNC_EVENT toggleFlags)
///
/// Both contexts use the same bit encoding for scroll/num/caps/kana locks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct LockKeys {
    pub scroll_lock: bool,
    pub num_lock: bool,
    pub caps_lock: bool,
    pub kana_lock: bool,
}

impl LockKeys {
    /// Encode as u16 flags (MS-RDPBCGR §2.2.8.1.1.3.1.1.5).
    pub const fn to_flags(self) -> u16 {
        let mut flags = 0u16;
        if self.scroll_lock { flags |= 0x0001; }
        if self.num_lock { flags |= 0x0002; }
        if self.caps_lock { flags |= 0x0004; }
        if self.kana_lock { flags |= 0x0008; }
        flags
    }

    /// Decode from u16 flags.
    pub const fn from_flags(flags: u16) -> Self {
        Self {
            scroll_lock: flags & 0x0001 != 0,
            num_lock: flags & 0x0002 != 0,
            caps_lock: flags & 0x0004 != 0,
            kana_lock: flags & 0x0008 != 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// Keyboard state (512-bit bitfield)
// ══════════════════════════════════════════════════════════════

/// 512-bit bitfield tracking all keyboard scancode states.
#[derive(Debug, Clone, PartialEq, Eq)]
struct KeyboardState {
    bits: [u64; 8], // 8 × 64 = 512 bits
}

impl KeyboardState {
    const fn new() -> Self {
        Self { bits: [0; 8] }
    }

    #[inline]
    fn is_pressed(&self, sc: Scancode) -> bool {
        let idx = sc.index();
        let word = idx / 64;
        let bit = idx % 64;
        self.bits[word] & (1u64 << bit) != 0
    }

    #[inline]
    fn set_pressed(&mut self, sc: Scancode, pressed: bool) {
        let idx = sc.index();
        let word = idx / 64;
        let bit = idx % 64;
        if pressed {
            self.bits[word] |= 1u64 << bit;
        } else {
            self.bits[word] &= !(1u64 << bit);
        }
    }

    fn release_all(&mut self) {
        self.bits = [0; 8];
    }
}

// ══════════════════════════════════════════════════════════════
// Mouse state
// ══════════════════════════════════════════════════════════════

/// Mouse button + position state.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MouseState {
    buttons: u8, // 5 bits for 5 buttons
    x: u16,
    y: u16,
}

impl MouseState {
    const fn new() -> Self {
        Self { buttons: 0, x: 0, y: 0 }
    }

    #[inline]
    fn is_pressed(&self, button: MouseButton) -> bool {
        self.buttons & (1 << button.index()) != 0
    }

    #[inline]
    fn set_pressed(&mut self, button: MouseButton, pressed: bool) {
        if pressed {
            self.buttons |= 1 << button.index();
        } else {
            self.buttons &= !(1 << button.index());
        }
    }

    fn release_all(&mut self) {
        self.buttons = 0;
    }
}

// ══════════════════════════════════════════════════════════════
// InputDatabase
// ══════════════════════════════════════════════════════════════

/// Maximum number of operations that `release_all` can produce:
/// 512 scancodes + 5 mouse buttons.
pub const MAX_RELEASE_OPS: usize = 512 + MouseButton::ALL.len();

/// Input state tracker with diff-based event generation.
///
/// Tracks keyboard (512 scancodes) and mouse (5 buttons + position)
/// state, generating [`Operation`] events only when state actually changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputDatabase {
    keyboard: KeyboardState,
    mouse: MouseState,
    lock_keys: LockKeys,
}

impl InputDatabase {
    /// Create a new input database with all keys/buttons released.
    pub const fn new() -> Self {
        Self {
            keyboard: KeyboardState::new(),
            mouse: MouseState::new(),
            lock_keys: LockKeys {
                scroll_lock: false,
                num_lock: false,
                caps_lock: false,
                kana_lock: false,
            },
        }
    }

    /// Process a key press. Returns `Some(KeyPressed)` if the key was not already pressed.
    pub fn key_press(&mut self, sc: Scancode) -> Option<Operation> {
        if self.keyboard.is_pressed(sc) {
            return None; // Already pressed, suppress duplicate
        }
        self.keyboard.set_pressed(sc, true);
        Some(Operation::KeyPressed(sc))
    }

    /// Process a key release. Returns `Some(KeyReleased)` if the key was pressed.
    pub fn key_release(&mut self, sc: Scancode) -> Option<Operation> {
        if !self.keyboard.is_pressed(sc) {
            return None; // Already released
        }
        self.keyboard.set_pressed(sc, false);
        Some(Operation::KeyReleased(sc))
    }

    /// Check if a key is currently pressed.
    pub fn is_key_pressed(&self, sc: Scancode) -> bool {
        self.keyboard.is_pressed(sc)
    }

    /// Process a mouse button press. Returns `Some` if state changed.
    pub fn mouse_button_press(&mut self, button: MouseButton) -> Option<Operation> {
        if self.mouse.is_pressed(button) {
            return None;
        }
        self.mouse.set_pressed(button, true);
        Some(Operation::MouseButtonPressed(button))
    }

    /// Process a mouse button release. Returns `Some` if state changed.
    pub fn mouse_button_release(&mut self, button: MouseButton) -> Option<Operation> {
        if !self.mouse.is_pressed(button) {
            return None;
        }
        self.mouse.set_pressed(button, false);
        Some(Operation::MouseButtonReleased(button))
    }

    /// Check if a mouse button is currently pressed.
    pub fn is_mouse_button_pressed(&self, button: MouseButton) -> bool {
        self.mouse.is_pressed(button)
    }

    /// Process a mouse move. Returns `Some(MouseMove)` if position changed.
    pub fn mouse_move(&mut self, x: u16, y: u16) -> Option<Operation> {
        if self.mouse.x == x && self.mouse.y == y {
            return None;
        }
        self.mouse.x = x;
        self.mouse.y = y;
        Some(Operation::MouseMove { x, y })
    }

    /// Get the current mouse position.
    pub fn mouse_position(&self) -> (u16, u16) {
        (self.mouse.x, self.mouse.y)
    }

    /// Update lock key state and generate a synchronize event.
    ///
    /// Unlike other state-mutating methods, this always produces an event even if
    /// the lock state is unchanged. Per MS-RDPBCGR §2.2.8.1.1.3.1.1.5, synchronize
    /// events must be sent unconditionally on focus acquisition to ensure client and
    /// server lock key state is consistent.
    pub fn synchronize_event(&mut self, locks: LockKeys) -> Operation {
        self.lock_keys = locks;
        Operation::SynchronizeEvent(locks)
    }

    /// Get the current lock key state.
    pub fn lock_keys(&self) -> LockKeys {
        self.lock_keys
    }

    /// Release all keys and buttons (e.g., on focus loss).
    /// Returns the number of operations written to `ops`.
    ///
    /// Mouse position (`x`, `y`) is intentionally NOT reset — position is not
    /// a "pressed" state and will be updated on the next `mouse_move` call.
    pub fn release_all(&mut self, ops: &mut [Operation; MAX_RELEASE_OPS]) -> usize {
        let mut count = 0;

        // Release all keyboard keys (512 scancodes max)
        for i in 0..512 {
            let sc = Scancode::from_index(i);
            if self.keyboard.is_pressed(sc) {
                debug_assert!(count < ops.len());
                ops[count] = Operation::KeyReleased(sc);
                count += 1;
            }
        }

        // Release all mouse buttons (5 buttons max)
        for &button in &MouseButton::ALL {
            if self.mouse.is_pressed(button) {
                debug_assert!(count < ops.len());
                ops[count] = Operation::MouseButtonReleased(button);
                count += 1;
            }
        }

        self.keyboard.release_all();
        self.mouse.release_all();

        count
    }
}

impl Default for InputDatabase {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Scancode ──

    #[test]
    fn scancode_index_roundtrip() {
        for code in 0..=255u8 {
            for extended in [false, true] {
                let sc = Scancode::new(code, extended);
                let idx = sc.index();
                let back = Scancode::from_index(idx);
                assert_eq!(back, sc);
            }
        }
    }

    #[test]
    fn scancode_index_range() {
        assert_eq!(Scancode::new(0, false).index(), 0);
        assert_eq!(Scancode::new(255, false).index(), 255);
        assert_eq!(Scancode::new(0, true).index(), 256);
        assert_eq!(Scancode::new(255, true).index(), 511);
    }

    // ── LockKeys ──

    #[test]
    fn lock_keys_flags_roundtrip() {
        let locks = LockKeys {
            scroll_lock: true,
            num_lock: false,
            caps_lock: true,
            kana_lock: false,
        };
        let flags = locks.to_flags();
        assert_eq!(flags, 0x0005); // scroll + caps
        let back = LockKeys::from_flags(flags);
        assert_eq!(back, locks);
    }

    #[test]
    fn lock_keys_all_set() {
        let locks = LockKeys::from_flags(0x000F);
        assert!(locks.scroll_lock);
        assert!(locks.num_lock);
        assert!(locks.caps_lock);
        assert!(locks.kana_lock);
    }

    // ── Key press/release ──

    #[test]
    fn key_press_generates_event() {
        let mut db = InputDatabase::new();
        let sc = Scancode::new(0x1E, false); // 'A'
        let op = db.key_press(sc);
        assert_eq!(op, Some(Operation::KeyPressed(sc)));
        assert!(db.is_key_pressed(sc));
    }

    #[test]
    fn key_press_duplicate_suppressed() {
        let mut db = InputDatabase::new();
        let sc = Scancode::new(0x1E, false);
        db.key_press(sc);
        let op = db.key_press(sc); // duplicate
        assert_eq!(op, None);
    }

    #[test]
    fn key_release_generates_event() {
        let mut db = InputDatabase::new();
        let sc = Scancode::new(0x1E, false);
        db.key_press(sc);
        let op = db.key_release(sc);
        assert_eq!(op, Some(Operation::KeyReleased(sc)));
        assert!(!db.is_key_pressed(sc));
    }

    #[test]
    fn key_release_without_press_suppressed() {
        let mut db = InputDatabase::new();
        let sc = Scancode::new(0x1E, false);
        let op = db.key_release(sc);
        assert_eq!(op, None);
    }

    #[test]
    fn extended_key_independent() {
        let mut db = InputDatabase::new();
        let normal = Scancode::new(0x1D, false); // Left Ctrl
        let extended = Scancode::new(0x1D, true); // Right Ctrl
        db.key_press(normal);
        assert!(db.is_key_pressed(normal));
        assert!(!db.is_key_pressed(extended));
    }

    // ── Mouse button ──

    #[test]
    fn mouse_button_press_release() {
        let mut db = InputDatabase::new();
        let op = db.mouse_button_press(MouseButton::Left);
        assert_eq!(op, Some(Operation::MouseButtonPressed(MouseButton::Left)));
        assert!(db.is_mouse_button_pressed(MouseButton::Left));

        let op = db.mouse_button_release(MouseButton::Left);
        assert_eq!(op, Some(Operation::MouseButtonReleased(MouseButton::Left)));
        assert!(!db.is_mouse_button_pressed(MouseButton::Left));
    }

    #[test]
    fn mouse_button_duplicate_suppressed() {
        let mut db = InputDatabase::new();
        db.mouse_button_press(MouseButton::Right);
        assert_eq!(db.mouse_button_press(MouseButton::Right), None);
    }

    #[test]
    fn multiple_buttons_independent() {
        let mut db = InputDatabase::new();
        db.mouse_button_press(MouseButton::Left);
        db.mouse_button_press(MouseButton::Right);
        assert!(db.is_mouse_button_pressed(MouseButton::Left));
        assert!(db.is_mouse_button_pressed(MouseButton::Right));
        assert!(!db.is_mouse_button_pressed(MouseButton::Middle));
    }

    // ── Mouse move ──

    #[test]
    fn mouse_move_generates_event() {
        let mut db = InputDatabase::new();
        let op = db.mouse_move(100, 200);
        assert_eq!(op, Some(Operation::MouseMove { x: 100, y: 200 }));
        assert_eq!(db.mouse_position(), (100, 200));
    }

    #[test]
    fn mouse_move_same_position_suppressed() {
        let mut db = InputDatabase::new();
        db.mouse_move(100, 200);
        let op = db.mouse_move(100, 200);
        assert_eq!(op, None);
    }

    // ── Wheel ──

    #[test]
    fn wheel_rotations_always_generates() {
        let op = Operation::wheel_rotations(-120);
        assert_eq!(op, Operation::WheelRotations(-120));
    }

    #[test]
    fn horizontal_wheel_rotations() {
        let op = Operation::horizontal_wheel_rotations(120);
        assert_eq!(op, Operation::HorizontalWheelRotations(120));
    }

    // ── Synchronize ──

    #[test]
    fn synchronize_event_updates_locks() {
        let mut db = InputDatabase::new();
        let locks = LockKeys { scroll_lock: false, num_lock: true, caps_lock: true, kana_lock: false };
        let op = db.synchronize_event(locks);
        assert_eq!(op, Operation::SynchronizeEvent(locks));
        assert_eq!(db.lock_keys(), locks);
    }

    // ── Release all ──

    #[test]
    fn release_all_generates_events() {
        let mut db = InputDatabase::new();
        db.key_press(Scancode::new(0x1E, false)); // A
        db.key_press(Scancode::new(0x1D, true));  // Right Ctrl
        db.mouse_button_press(MouseButton::Left);

        let mut ops = [Operation::KeyPressed(Scancode::new(0, false)); MAX_RELEASE_OPS];
        let count = db.release_all(&mut ops);

        assert_eq!(count, 3);
        assert!(!db.is_key_pressed(Scancode::new(0x1E, false)));
        assert!(!db.is_key_pressed(Scancode::new(0x1D, true)));
        assert!(!db.is_mouse_button_pressed(MouseButton::Left));
    }

    #[test]
    fn release_all_empty_state() {
        let mut db = InputDatabase::new();
        let mut ops = [Operation::KeyPressed(Scancode::new(0, false)); MAX_RELEASE_OPS];
        let count = db.release_all(&mut ops);
        assert_eq!(count, 0);
    }

    // ── All 512 scancodes ──

    #[test]
    fn all_512_scancodes() {
        let mut db = InputDatabase::new();
        for i in 0..512 {
            let sc = Scancode::from_index(i);
            assert!(db.key_press(sc).is_some());
            assert!(db.is_key_pressed(sc));
        }
        for i in 0..512 {
            let sc = Scancode::from_index(i);
            assert!(db.key_release(sc).is_some());
            assert!(!db.is_key_pressed(sc));
        }
    }

    // ── Gap tests ──

    #[test]
    fn keyboard_word_boundary_scancodes() {
        let boundaries = [63, 64, 127, 128, 255, 256, 319, 320, 447, 448, 511];
        for &idx in &boundaries {
            let mut db = InputDatabase::new();
            let sc = Scancode::from_index(idx);
            db.key_press(sc);
            assert!(db.is_key_pressed(sc), "failed at index {idx}");
            // Neighbour must not be contaminated
            let neighbour = Scancode::from_index((idx + 1) % 512);
            assert!(!db.is_key_pressed(neighbour), "neighbour contaminated at {idx}");
        }
    }

    #[test]
    fn release_all_operation_contents() {
        let mut db = InputDatabase::new();
        let sc_a = Scancode::new(0x1E, false);
        let sc_ctrl = Scancode::new(0x1D, true);
        db.key_press(sc_a);
        db.key_press(sc_ctrl);
        db.mouse_button_press(MouseButton::X1);
        db.mouse_button_press(MouseButton::X2);

        let mut ops = [Operation::KeyPressed(Scancode::new(0, false)); MAX_RELEASE_OPS];
        let count = db.release_all(&mut ops);
        assert_eq!(count, 4);
        let actual = &ops[..count];
        assert!(actual.contains(&Operation::KeyReleased(sc_a)));
        assert!(actual.contains(&Operation::KeyReleased(sc_ctrl)));
        assert!(actual.contains(&Operation::MouseButtonReleased(MouseButton::X1)));
        assert!(actual.contains(&Operation::MouseButtonReleased(MouseButton::X2)));
    }

    #[test]
    fn release_all_all_mouse_buttons() {
        let mut db = InputDatabase::new();
        for &btn in &MouseButton::ALL {
            db.mouse_button_press(btn);
        }
        let mut ops = [Operation::KeyPressed(Scancode::new(0, false)); MAX_RELEASE_OPS];
        let count = db.release_all(&mut ops);
        assert_eq!(count, 5);
        for &btn in &MouseButton::ALL {
            assert!(!db.is_mouse_button_pressed(btn));
        }
    }

    #[test]
    fn lock_keys_individual_flag_bits() {
        let s = LockKeys { scroll_lock: true, num_lock: false, caps_lock: false, kana_lock: false };
        assert_eq!(s.to_flags(), 0x0001);
        let n = LockKeys { scroll_lock: false, num_lock: true, caps_lock: false, kana_lock: false };
        assert_eq!(n.to_flags(), 0x0002);
        let c = LockKeys { scroll_lock: false, num_lock: false, caps_lock: true, kana_lock: false };
        assert_eq!(c.to_flags(), 0x0004);
        let k = LockKeys { scroll_lock: false, num_lock: false, caps_lock: false, kana_lock: true };
        assert_eq!(k.to_flags(), 0x0008);
    }

    #[test]
    fn unicode_operation_variants() {
        let pressed = Operation::UnicodeKeyPressed(0x0041);
        let released = Operation::UnicodeKeyReleased(0x0041);
        assert_ne!(pressed, released);
    }

    #[test]
    fn mouse_move_partial_axis() {
        let mut db = InputDatabase::new();
        db.mouse_move(100, 200);
        assert_eq!(db.mouse_move(101, 200), Some(Operation::MouseMove { x: 101, y: 200 }));
        assert_eq!(db.mouse_move(101, 201), Some(Operation::MouseMove { x: 101, y: 201 }));
    }

    #[test]
    fn mouse_move_back_to_origin() {
        let mut db = InputDatabase::new();
        db.mouse_move(100, 200);
        assert_eq!(db.mouse_move(0, 0), Some(Operation::MouseMove { x: 0, y: 0 }));
    }

    #[test]
    fn wheel_boundary_deltas() {
        assert_eq!(Operation::wheel_rotations(0), Operation::WheelRotations(0));
        assert_eq!(Operation::wheel_rotations(i16::MAX), Operation::WheelRotations(i16::MAX));
        assert_eq!(Operation::wheel_rotations(i16::MIN), Operation::WheelRotations(i16::MIN));
    }
}

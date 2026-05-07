import { useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { keyEventToScancode } from "./keymap";

interface RdpCanvasProps {
  sessionId: number;
  /** Canvas ref owned by the parent so the rendering listener
   *  (`listen("rdp:event")`) and the input listener (this component)
   *  share the same DOM node — putImageData and event handlers
   *  both target this surface. */
  canvasRef: React.RefObject<HTMLCanvasElement | null>;
  width: number;
  height: number;
}

/**
 * Interactive RDP surface. Owns the canvas DOM node's keyboard,
 * mouse, wheel, and blur listeners and forwards them to the backend
 * via the `rdp_send_input` Tauri command.
 *
 * Held-key tracking: every key currently in `keydown` state is kept
 * in a Set so a `blur` event can synthesise `keyup`s for all of them
 * — without that, a Shift held while the user Alt-Tabs away would
 * stay logically pressed on the remote and break the next session.
 */
export function RdpCanvas({ sessionId, canvasRef, width, height }: RdpCanvasProps) {
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const heldKeys = new Set<string>();
    let mouseX = 0;
    let mouseY = 0;

    const sendInput = (event: object) => {
      invoke("rdp_send_input", { id: sessionId, event }).catch((err) =>
        console.error("rdp_send_input failed:", err),
      );
    };

    const clampX = (clientX: number) => {
      const rect = canvas.getBoundingClientRect();
      return Math.max(0, Math.min(width - 1, Math.round(clientX - rect.left)));
    };
    const clampY = (clientY: number) => {
      const rect = canvas.getBoundingClientRect();
      return Math.max(0, Math.min(height - 1, Math.round(clientY - rect.top)));
    };

    const onKeyDown = (e: KeyboardEvent) => {
      // Suppress browser auto-repeat — the remote OS handles repeat
      // itself. Without this the wire fills with redundant keydowns.
      if (e.repeat) {
        e.preventDefault();
        return;
      }
      const sc = keyEventToScancode(e.code);
      if (sc) {
        e.preventDefault();
        heldKeys.add(e.code);
        sendInput({ kind: "key", code: sc.code, extended: sc.extended, pressed: true });
      }
    };

    const onKeyUp = (e: KeyboardEvent) => {
      const sc = keyEventToScancode(e.code);
      if (sc) {
        e.preventDefault();
        heldKeys.delete(e.code);
        sendInput({ kind: "key", code: sc.code, extended: sc.extended, pressed: false });
      }
    };

    const onMouseMove = (e: MouseEvent) => {
      mouseX = clampX(e.clientX);
      mouseY = clampY(e.clientY);
      sendInput({ kind: "mouse_move", x: mouseX, y: mouseY });
    };

    const onMouseDown = (e: MouseEvent) => {
      mouseX = clampX(e.clientX);
      mouseY = clampY(e.clientY);
      sendInput({ kind: "mouse_button", button: e.button, pressed: true, x: mouseX, y: mouseY });
      e.preventDefault();
    };

    const onMouseUp = (e: MouseEvent) => {
      mouseX = clampX(e.clientX);
      mouseY = clampY(e.clientY);
      sendInput({ kind: "mouse_button", button: e.button, pressed: false, x: mouseX, y: mouseY });
      e.preventDefault();
    };

    const onWheel = (e: WheelEvent) => {
      // Browsers report deltaY positive = "scroll content down",
      // which on an RDP wire means "wheel rotated *toward* user".
      // Negate so positive wheel delta = away (matches Windows
      // WHEEL_DELTA convention).
      const horizontal = Math.abs(e.deltaX) > Math.abs(e.deltaY);
      const raw = horizontal ? e.deltaX : e.deltaY;
      const delta = Math.max(-32768, Math.min(32767, -Math.round(raw)));
      sendInput({ kind: "wheel", delta, horizontal, x: mouseX, y: mouseY });
      e.preventDefault();
    };

    const onBlur = () => {
      // Snapshot before the loop because each sendInput is async
      // (fire-and-forget) but we mutate the set right here.
      const held = Array.from(heldKeys);
      heldKeys.clear();
      for (const code of held) {
        const sc = keyEventToScancode(code);
        if (sc) {
          sendInput({ kind: "key", code: sc.code, extended: sc.extended, pressed: false });
        }
      }
    };

    const onContextMenu = (e: MouseEvent) => {
      // Let right-click reach the remote instead of opening the
      // browser context menu.
      e.preventDefault();
    };

    canvas.addEventListener("keydown", onKeyDown);
    canvas.addEventListener("keyup", onKeyUp);
    canvas.addEventListener("mousemove", onMouseMove);
    canvas.addEventListener("mousedown", onMouseDown);
    canvas.addEventListener("mouseup", onMouseUp);
    canvas.addEventListener("wheel", onWheel, { passive: false });
    canvas.addEventListener("blur", onBlur);
    canvas.addEventListener("contextmenu", onContextMenu);

    return () => {
      canvas.removeEventListener("keydown", onKeyDown);
      canvas.removeEventListener("keyup", onKeyUp);
      canvas.removeEventListener("mousemove", onMouseMove);
      canvas.removeEventListener("mousedown", onMouseDown);
      canvas.removeEventListener("mouseup", onMouseUp);
      canvas.removeEventListener("wheel", onWheel);
      canvas.removeEventListener("blur", onBlur);
      canvas.removeEventListener("contextmenu", onContextMenu);
    };
  }, [sessionId, canvasRef, width, height]);

  return (
    <canvas
      ref={canvasRef}
      width={width}
      height={height}
      className="rdp-canvas"
      tabIndex={0}
    />
  );
}

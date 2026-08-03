/**
 * Rendering the link offer as a QR code.
 *
 * The phone's Devices screen scans; it has no paste path. So this is not a
 * nicety — without it the flow cannot complete.
 *
 * ## Why it is small now
 *
 * It was not. The offer used to carry the session's X-Wing public key —
 * **1216 bytes**, because post-quantum keys are large — which after two base64
 * layers was ~2360 characters. That is QR version 36, a 161×161 grid that only
 * fits at error-correction level L, and phones would not read it.
 *
 * The QR now carries a 32-byte **commitment** to those keys instead, and the
 * keys travel over the network where the phone verifies them against it. The
 * eyes still carry the trust anchor — a substituted key hashes differently and
 * is refused — but the payload is 102 characters, which is version 8 at error
 * correction **Q**. Sixteen times smaller *and* on a stronger EC level than
 * the old one could reach.
 */
import qrcode from 'qrcode-generator';

/** Draw `text` into a canvas, dark-on-light with a proper quiet zone. */
export function renderQr(text: string, pixels = 360): HTMLCanvasElement {
  // Level Q — 25% recovery. Affordable now that the payload is small, and
  // worth spending: glare and angle were exactly what defeated the old code.
  const qr = qrcode(0, 'Q');
  qr.addData(text, 'Byte');
  qr.make();

  const count = qr.getModuleCount();
  // Four modules of quiet zone is what the spec asks for, and scanners really
  // do need it — a QR flush to the edge of a dark page often will not read.
  const quiet = 4;
  const total = count + quiet * 2;
  // Integer module size, so modules land on whole pixels. A fractional size
  // produces seams that a camera reads as noise.
  const scale = Math.max(2, Math.floor(pixels / total));

  const canvas = document.createElement('canvas');
  const side = total * scale;
  canvas.width = side;
  canvas.height = side;
  canvas.style.width = '100%';
  canvas.style.maxWidth = `${side}px`;
  canvas.style.imageRendering = 'pixelated';

  const ctx = canvas.getContext('2d')!;
  // White quiet zone and white background, always — not the page's dark
  // surface. Scanners expect dark-on-light, and an inverted QR is a coin flip.
  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, side, side);
  ctx.fillStyle = '#000000';
  for (let row = 0; row < count; row++) {
    for (let col = 0; col < count; col++) {
      if (qr.isDark(row, col)) {
        ctx.fillRect((col + quiet) * scale, (row + quiet) * scale, scale, scale);
      }
    }
  }
  return canvas;
}

/** How dense the code came out, for the UI to say so honestly. */
export function qrVersion(text: string): number {
  const qr = qrcode(0, 'Q');
  qr.addData(text, 'Byte');
  qr.make();
  return (qr.getModuleCount() - 17) / 4;
}

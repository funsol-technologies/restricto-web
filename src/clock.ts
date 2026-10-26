/** Server-aligned unix seconds; the browser clock is often wrong and the signature window is only ±90 s. */
export class Clock {
  offset = 0;

  now(): number {
    return Math.floor(Date.now() / 1000) + this.offset;
  }

  sync(serverTime: number): void {
    if (Number.isFinite(serverTime) && serverTime > 0) this.offset = Math.floor(serverTime) - Math.floor(Date.now() / 1000);
  }
}

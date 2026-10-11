/**
 * How long a send keeps trying, and how long it waits between tries — the
 * same numbers as the app (`chat_state.dart`): a retry sweep that backs off
 * from 30 seconds to 30 minutes and gives up after seven days.
 */

/** A pending send stops being retried this long after it was first tried. */
export const SEND_GIVE_UP_AFTER_MS = 7 * 24 * 3600 * 1000;

const RETRY_BASE_MS = 30 * 1000;
const RETRY_CEILING_MS = 30 * 60 * 1000;

/** How long to wait after the `attempts`th failure before trying again. */
export function sendBackoffMs(attempts: number): number {
  if (attempts <= 0) return 0;
  const shift = Math.min(Math.max(attempts - 1, 0), 20);
  return Math.min(Math.max(RETRY_BASE_MS * 2 ** shift, RETRY_BASE_MS), RETRY_CEILING_MS);
}

/** Senders offer edit and delete-for-everyone for this long. */
export const EDIT_WINDOW_MS = 24 * 3600 * 1000;
/** Receivers allow this much more, to absorb clock skew and queue delay. */
export const EDIT_GRACE_MS = 12 * 3600 * 1000;

/** A `typing` is shown this long without a refresh, and re-sent this often
 * while typing continues. */
export const TYPING_TTL_MS = 15 * 1000;
export const TYPING_REFRESH_MS = 8 * 1000;

/** A roster is asked for at most once per group and version in this window,
 * and answered at most once per member in the other. */
export const ROSTER_ASK_EVERY_MS = 10 * 60 * 1000;
export const ROSTER_ANSWER_EVERY_MS = 60 * 1000;

/** Parked group messages: at most this many, kept at most this long. */
export const PARKED_MAX = 200;
export const PARKED_TTL_MS = 7 * 24 * 3600 * 1000;

/** A `reply_to` preview is clipped to this many characters by the sender. */
export const REPLY_PREVIEW_MAX = 140;

/** Signed prekeys are replaced once older than this. */
export const SPK_ROTATE_MS = 7 * 24 * 3600 * 1000;

/** One-time pools are topped up to this many of each kind. */
export const OPK_TARGET = 32;

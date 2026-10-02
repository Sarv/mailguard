/**
 * Reading raw header text — the primitives, with no rules attached.
 *
 * Zero dependencies by contract, and the reason the contract matters: a bulk
 * sender is identified by headers the RFCs reserve for it (RFC 2919 `List-Id`,
 * RFC 2369 `List-Unsubscribe`, `Precedence`, RFC 3834 `Auto-Submitted`), and
 * the answer has to be the SAME one on both sides of an application — the
 * sync that files the message and the view that renders it. A UI that reaches
 * for it must not have to import the scanner to get it: the header RULES pull
 * in an address parser and a freemail corpus, and in a browser bundle that is
 * dead weight at best and a blank window at worst.
 *
 * So this entry point is the lookup and the bulk predicate, and nothing that
 * costs a dependency. Origin-IP extraction reads headers too but needs an IP
 * parser, and stays in the main entry for that reason alone.
 */
export {
  headerLookupFromText,
  headerValueFromText,
  headerValuesFromText,
  type HeaderLookup,
} from './lookup.js';
export {
  bulkHeaderSignals,
  hasBulkHeaderSignal,
  BULK_HEADER_NAMES,
  type BulkHeaderSignals,
} from './bulk.js';
export {
  extractAuthHeaderBlock,
  parseAuthenticationHeaders,
  parseAuthResultsHeader,
  type AuthResult,
  type AuthResultsHeader,
  type AuthResultsOptions,
} from './auth-results.js';
export { receivedAt, receivedAtFromLine } from './received-date.js';

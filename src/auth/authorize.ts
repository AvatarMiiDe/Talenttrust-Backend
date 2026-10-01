/**
 * @module authorize
 * @description Core authorization logic for TalentTrust.
 *
 * Provides `isAllowed` — a pure function that checks whether a given role
 * is permitted to perform a specific action on a resource, based on the
 * access control matrix defined in `roles.ts`.
 *
 * Security notes:
 *   - Unknown roles are denied by default (deny-by-default).
 *   - Unknown resources or actions are denied by default.
 *   - No runtime mutation of the matrix is permitted from this module.
 *
 * Determinism and recovery notes:
 *   - `isAllowed` is a pure function of its arguments and the immutable
 *     ACCESS_CONTROL_MATRIX. It never mutates state, never throws for well-
 *     typed inputs, and always returns a boolean. This makes failure
 *     recovery deterministic: the same inputs always produce the same
 *     decision, regardless of concurrency or retries.
 *   - Any unexpected error while evaluating the matrix is treated as a
 *     deny (fail-closed) and reported through the injectable logger so
 *     operators can diagnose failures without exposing sensitive data.
 *   - The decision is stable across retries and concurrent execution because
 *     there is no shared mutable state involved.
 */

import {
  Role,
  Resource,
  Action,
  ACCESS_CONTROL_MATRIX,
  VALID_ROLES,
  VALID_RESOURCES,
  VALID_ACTIONS,
} from './roles';

/**
 * The set of identifiers that are considered valid for each dimension.
 *
 * These are derived from the canonical definitions in `roles.ts` so the
 * validation boundaries cannot drift away from the access control matrix.
 */
const VALID_ROLE_SET: ReadonlySet<string> = new Set(VALID_ROLES);
const VALID_RESOURCE_SET: ReadonlySet<string> = new Set(VALID_RESOURCES);
const VALID_ACTION_SET: ReadonlySet<string> = new Set(VALID_ACTIONS);

/**
 * Returns true only when the value is a non-empty string.
 *
 * This is the first validation boundary: runtime callers may pass null,
 * undefined, numbers, objects, or empty strings despite the TypeScript
 * types. The authorization function must not throw on such inputs.
 */
function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

/**
 * Deep-freeze a value and recursively all of its own enumerable properties.
 *
 * This is used to make the access control matrix immutable at runtime.
 * Immutability is the key invariant that guarantees concurrent calls to
 * `isAllowed` observe a consistent snapshot of the matrix and therefore cannot
 * produce stale or inconsistent authorization results.
 *
 * Care is taken to tolerate non-object values and cycles safely:
 *   - Primitives and null/undefined are returned as-is.
 *   - Already-frozen objects are skipped to avoid redundant work and cycles.
 */
function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== 'object') {
    return value;
  }

  if (Object.isFrozen(value)) {
    return value;
  }

  Object.freeze(value);

  for (const key of Object.getOwnPropertyNames(value)) {
    const child = (value as Record<string, unknown>)[key];
    if (child !== null && typeof child === 'object') {
      deepFreeze(child);
    }
  }

  return value;
}

/**
 * The authorization matrix used at runtime.
 *
 * It is a deep-frozen view of `ACCESS_CONTROL_MATRIX` so that concurrent
 * callers cannot observe or cause mutations. The reference is captured once at
 * module load and never replaced.
 */
const FROZEN_MATRIX = deepFreeze(ACCESS_CONTROL_MATRIX);

/**
 * Structured logger contract used by this module.
 *
 * Implementations must not log raw user identity or credentials. The
 * authorization decision is deterministic and the logger is only used
 * for diagnosing unexpected failures.
 */
export interface AuthorizationLogger {
  warn(message: string, context?: Record<unknown, unknown>): void;
  error(message: string, context?: Record<unknown, unknown>): void;
}

const noopLogger: AuthorizationLogger = {
  warn() {
    /* no-op by default; callers may inject a logger */
  },
  error() {
    /* no-op by default; callers may inject a logger */
  },
};

let activeLogger: AuthorizationLogger = noopLogger;

/**
 * Replace the logger used for diagnostic events. Returns the previous
 * logger so callers (e.g. tests) can restore it deterministically.
 */
export function setAuthorizationLogger(logger: AuthorizationLogger): AuthorizationLogger {
  const previous = activeLogger;
  activeLogger = logger ?? noopLogger;
  return previous;
}

/**
 * Reset the logger to the default no-op implementation. Primarily used
 * by tests to avoid cross-test interference.
 */
export function resetAuthorizationLogger(): void {
  activeLogger = noopLogger;
}

/**
 * Check whether a role is permitted to perform an action on a resource.
 *
 * This function is pure with respect to the access control matrix and
 * its arguments. It is safe to call concurrently and idempotent under
 * retries. Any unexpected failure during evaluation fails closed (denied)
 * and is reported through the active logger.
 *
 * @param role     - The user's role.
 * @param resource - The target resource.
 * @param action   - The requested action.
 * @returns `true` if the action is allowed, `false` otherwise.
 */
export function isAllowed(role: Role, resource: Resource, action: Action): boolean {
  try {
    // Guard against non-string / nullish inputs that can arrive from
    // untrusted request payloads despite the TypeScript types.
    if (typeof role !== 'string' || typeof resource !== 'string' || typeof action !== 'string') {
      activeLogger.warn('authorization.denied.invalid_input_type', {
        roleType: typeof role,
        resourceType: typeof resource,
        actionType: typeof action,
      });
      return false;
    }

    if (!VALID_ROLE_SET.has(role)) {
      // Unknown role — deny by default. We do not log the raw role
      // value to avoid leaking potentially sensitive identifiers.
      activeLogger.warn('authorization.denied.unknown_role');
      return false;
    }

    if (!VALID_RESOURCE_SET.has(resource)) {
      // Unknown resource — deny by default.
      activeLogger.warn('authorization.denied.unknown_resource');
      return false;
    }

    if (!VALID_ACTION_SET.has(action)) {
      // Unknown action — deny by default.
      activeLogger.warn('authorization.denied.unknown_action');
      return false;
    }

    const permissions = FROZEN_MATRIX[role as Role];
    if (!permissions) {
      activeLogger.warn('authorization.denied.unknown_role');
      return false;
    }

    const actions = permissions[resource as Resource];
    if (!actions) {
      activeLogger.warn('authorization.denied.unknown_resource');
      return false;
    }

    // `Array.prototype.includes` is stable and deterministic for the
    // immutable matrix arrays. Unknown actions simply yield `false`.
    return actions.includes(action as Action);
  } catch (error) {
    // Fail closed: any unexpected error results in a deny. We log a
    // sanitized message only — never the raw inputs — so failures are
    // observable without exposing sensitive data.
    activeLogger.error('authorization.error.fail_closed', {
      message: error instanceof Error ? error.message : 'unknown error',
    });
    return false;
  }
}

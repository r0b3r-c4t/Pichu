export const VEHICLE_STATUSES = ['ACTIVE', 'ARCHIVED'] as const;
export type VehicleStatus = (typeof VEHICLE_STATUSES)[number];

export const MEMBERSHIP_ROLES = ['OWNER', 'MEMBER'] as const;
export type MembershipRole = (typeof MEMBERSHIP_ROLES)[number];

export const MEMBERSHIP_STATUSES = ['ACTIVE', 'SUSPENDED', 'REVOKED'] as const;
export type MembershipStatus = (typeof MEMBERSHIP_STATUSES)[number];

export const INVITATION_STATUSES = ['PENDING', 'ACCEPTED', 'REVOKED', 'EXPIRED'] as const;
export type InvitationStatus = (typeof INVITATION_STATUSES)[number];

export const INVITATION_TARGET_ROLES = ['MEMBER'] as const;
export type InvitationTargetRole = (typeof INVITATION_TARGET_ROLES)[number];

export const ACCESS_GRANT_SCOPE_TYPES = ['VEHICLE', 'DEVICE', 'MODULE'] as const;
export type AccessGrantScopeType = (typeof ACCESS_GRANT_SCOPE_TYPES)[number];

export const ACCESS_GRANT_CHANNELS = ['ONLINE', 'BLE_OFFLINE', 'ANY'] as const;
export type AccessGrantChannel = (typeof ACCESS_GRANT_CHANNELS)[number];

export const ACCESS_GRANT_STATUSES = ['ACTIVE', 'REVOKED', 'EXPIRED'] as const;
export type AccessGrantStatus = (typeof ACCESS_GRANT_STATUSES)[number];

export const DEFAULT_INVITATION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

export const ALLOWED_VEHICLE_STATUS_TRANSITIONS: Readonly<
  Record<VehicleStatus, readonly VehicleStatus[]>
> = {
  ACTIVE: ['ARCHIVED'],
  ARCHIVED: [],
};

export const ALLOWED_MEMBERSHIP_STATUS_TRANSITIONS: Readonly<
  Record<MembershipStatus, readonly MembershipStatus[]>
> = {
  ACTIVE: ['SUSPENDED', 'REVOKED'],
  SUSPENDED: ['ACTIVE', 'REVOKED'],
  REVOKED: [],
};

export const ALLOWED_INVITATION_STATUS_TRANSITIONS: Readonly<
  Record<InvitationStatus, readonly InvitationStatus[]>
> = {
  PENDING: ['ACCEPTED', 'REVOKED', 'EXPIRED'],
  ACCEPTED: [],
  REVOKED: [],
  EXPIRED: [],
};

export const ALLOWED_ACCESS_GRANT_STATUS_TRANSITIONS: Readonly<
  Record<AccessGrantStatus, readonly AccessGrantStatus[]>
> = {
  ACTIVE: ['REVOKED', 'EXPIRED'],
  REVOKED: [],
  EXPIRED: [],
};

export function canTransitionVehicleStatus(from: VehicleStatus, to: VehicleStatus): boolean {
  return ALLOWED_VEHICLE_STATUS_TRANSITIONS[from].includes(to);
}

export function canTransitionMembershipStatus(
  from: MembershipStatus,
  to: MembershipStatus,
): boolean {
  return ALLOWED_MEMBERSHIP_STATUS_TRANSITIONS[from].includes(to);
}

export function canTransitionInvitationStatus(
  from: InvitationStatus,
  to: InvitationStatus,
): boolean {
  return ALLOWED_INVITATION_STATUS_TRANSITIONS[from].includes(to);
}

export function canTransitionAccessGrantStatus(
  from: AccessGrantStatus,
  to: AccessGrantStatus,
): boolean {
  return ALLOWED_ACCESS_GRANT_STATUS_TRANSITIONS[from].includes(to);
}

/**
 * Permissions strictly reserved to the canonical OWNER.
 * Never assignable via Invitation, MEMBER Membership, or AccessGrant.
 */
export const OWNER_RESERVED_PERMISSIONS = [
  'vehicle:owner',
  'vehicle:delete',
  'vehicle:archive',
  'vehicle:transfer-ownership',
  'membership:manage',
  'access-grant:manage',
] as const;
export type OwnerReservedPermission = (typeof OWNER_RESERVED_PERMISSIONS)[number];

/** Known delegable permissions at the vehicle level. */
export const DELEGABLE_VEHICLE_PERMISSIONS = [
  'vehicle:read',
  'vehicle:update',
  'vehicle:manage',
  'invitation:create',
  'device:read',
  'device:link',
] as const;

/** Known specific permissions for VEHICLE-scoped AccessGrants (non-administrative). */
export const ACCESS_GRANT_VEHICLE_PERMISSIONS = [
  'vehicle:read',
  'vehicle:update',
  'device:read',
  'device:link',
] as const;

/** Known specific permissions for DEVICE-scoped AccessGrants. */
export const ACCESS_GRANT_DEVICE_PERMISSIONS = [
  'device:read',
  'device:connect',
  'device:command',
] as const;

/** Known specific permissions for MODULE-scoped AccessGrants (brand/module agnostic). */
export const ACCESS_GRANT_MODULE_PERMISSIONS = [
  'module:read',
  'module:configure',
  'module:actuate',
] as const;

export const DELEGABLE_MEMBERSHIP_PERMISSIONS = [
  ...DELEGABLE_VEHICLE_PERMISSIONS,
  'device:connect',
  'device:command',
  ...ACCESS_GRANT_MODULE_PERMISSIONS,
] as const;
export type DelegableMembershipPermission = (typeof DELEGABLE_MEMBERSHIP_PERMISSIONS)[number];

export const ALL_KNOWN_PERMISSIONS = [
  ...OWNER_RESERVED_PERMISSIONS,
  ...DELEGABLE_MEMBERSHIP_PERMISSIONS,
] as const;
export type KnownVehiclePermission = (typeof ALL_KNOWN_PERMISSIONS)[number];

const ownerReservedSet = new Set<string>(OWNER_RESERVED_PERMISSIONS);
const delegableMembershipSet = new Set<string>(DELEGABLE_MEMBERSHIP_PERMISSIONS);
const allKnownSet = new Set<string>(ALL_KNOWN_PERMISSIONS);
const grantScopePermissions: Readonly<Record<AccessGrantScopeType, ReadonlySet<string>>> = {
  VEHICLE: new Set<string>(ACCESS_GRANT_VEHICLE_PERMISSIONS),
  DEVICE: new Set<string>(ACCESS_GRANT_DEVICE_PERMISSIONS),
  MODULE: new Set<string>(ACCESS_GRANT_MODULE_PERMISSIONS),
};

export function containsControlCharacter(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0) ?? 0;
    if (codePoint <= 0x1f || codePoint === 0x7f) {
      return true;
    }
  }
  return false;
}

export function normalizeOptionalText(value: string | null | undefined): string | null {
  if (value === null || value === undefined) {
    return null;
  }
  const trimmed = value.trim();
  return trimmed.length === 0 ? null : trimmed;
}

export function containsWildcardPermission(permission: string): boolean {
  return permission.includes('*');
}

export function isOwnerReservedPermission(permission: string): boolean {
  return ownerReservedSet.has(permission);
}

export function isKnownPermission(permission: string): permission is KnownVehiclePermission {
  if (
    typeof permission !== 'string' ||
    permission.length === 0 ||
    permission.length > 64 ||
    permission.trim() !== permission ||
    containsControlCharacter(permission) ||
    containsWildcardPermission(permission)
  ) {
    return false;
  }
  return allKnownSet.has(permission);
}

export function isDelegableMembershipPermission(
  permission: string,
): permission is DelegableMembershipPermission {
  return isKnownPermission(permission) && delegableMembershipSet.has(permission);
}

export function isAccessGrantPermissionForScope(
  scopeType: AccessGrantScopeType,
  permission: string,
): boolean {
  if (!isKnownPermission(permission) || isOwnerReservedPermission(permission)) {
    return false;
  }
  return grantScopePermissions[scopeType].has(permission);
}

export function validatePermissionSet(
  permissions: readonly string[],
  options: {
    minItems?: number;
    maxItems: number;
    allowPermission: (permission: string) => boolean;
  },
): boolean {
  const minItems = options.minItems ?? 0;
  if (
    !Array.isArray(permissions) ||
    permissions.length < minItems ||
    permissions.length > options.maxItems
  ) {
    return false;
  }

  const seen = new Set<string>();
  for (const permission of permissions) {
    if (typeof permission !== 'string' || !options.allowPermission(permission)) {
      return false;
    }
    if (seen.has(permission)) {
      return false;
    }
    seen.add(permission);
  }
  return true;
}

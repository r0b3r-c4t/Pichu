import { Types } from 'mongoose';
import { MembershipModel } from '../models/membership.model.js';
import { VehicleModel } from '../models/vehicle.model.js';
import { InvitationModel } from '../models/invitation.model.js';

export class VehicleServiceError extends Error {}
export async function createVehicle(
  userId: Types.ObjectId,
  input: {
    name: string;
    make?: string | null;
    model?: string | null;
    year?: number | null;
    engine?: string | null;
  },
) {
  const vehicle = await VehicleModel.create({ ownerUserId: userId, ...input });
  await MembershipModel.create({
    vehicleId: vehicle._id,
    userId,
    role: 'OWNER',
    permissions: ['vehicle:manage'],
  });
  return vehicle;
}
export async function canAccessVehicle(
  vehicleId: Types.ObjectId,
  userId: Types.ObjectId,
  permission?: string,
) {
  const membership = await MembershipModel.findOne({ vehicleId, userId });
  return Boolean(
    membership &&
    (!permission || membership.permissions.includes(permission) || membership.role === 'OWNER'),
  );
}

export async function listOwnedVehicles(userId: Types.ObjectId) {
  return VehicleModel.find({ ownerUserId: userId }).sort({ createdAt: 1 }).lean();
}

export async function getVehicleForUser(vehicleId: Types.ObjectId, userId: Types.ObjectId) {
  const allowed = await canAccessVehicle(vehicleId, userId);
  if (!allowed) return null;
  return VehicleModel.findById(vehicleId).lean();
}

export async function inviteMember(
  vehicleId: Types.ObjectId,
  inviterUserId: Types.ObjectId,
  inviteeUserId: Types.ObjectId,
  permissions: string[],
) {
  const allowed = await canAccessVehicle(vehicleId, inviterUserId, 'vehicle:manage');
  if (!allowed) return null;
  return InvitationModel.findOneAndUpdate(
    { vehicleId, inviteeUserId, status: 'PENDING' },
    {
      $set: {
        inviterUserId,
        permissions,
        status: 'PENDING',
        expiresAt: new Date(Date.now() + 7 * 86_400_000),
      },
    },
    { upsert: true, new: true, setDefaultsOnInsert: true },
  ).lean();
}

export async function acceptInvitation(invitationId: Types.ObjectId, userId: Types.ObjectId) {
  const invitation = await InvitationModel.findOneAndUpdate(
    { _id: invitationId, inviteeUserId: userId, status: 'PENDING', expiresAt: { $gt: new Date() } },
    { $set: { status: 'ACCEPTED', acceptedAt: new Date() } },
    { new: true },
  );
  if (!invitation) return null;
  return MembershipModel.findOneAndUpdate(
    { vehicleId: invitation.vehicleId, userId },
    { $set: { role: 'MEMBER', permissions: invitation.permissions } },
    { upsert: true, new: true, setDefaultsOnInsert: true },
  ).lean();
}

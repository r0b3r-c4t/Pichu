import { Types, type Model } from 'mongoose';
import { UserModel, type User } from '../models/user.model.js';

export interface PublicUserProfile {
  id: string;
  name: string;
  username: string | null;
  email: string;
  emailVerified: boolean;
  emailVerifiedAt: string | null;
}

export class UserProfileServiceError extends Error {
  readonly code = 'USER_PROFILE_UNAVAILABLE';

  constructor() {
    super('User profile is unavailable');
    this.name = 'UserProfileServiceError';
  }
}

export class UserProfileService {
  constructor(private readonly userModel: Model<User> = UserModel) {}

  async isEmailVerified(userId: string): Promise<boolean> {
    if (!Types.ObjectId.isValid(userId)) return false;
    try {
      return Boolean(
        await this.userModel.exists({ _id: userId, emailVerifiedAt: { $type: 'date' } }),
      );
    } catch {
      throw new UserProfileServiceError();
    }
  }

  async findById(userId: string): Promise<PublicUserProfile | null> {
    if (!Types.ObjectId.isValid(userId)) return null;
    try {
      const user = await this.userModel
        .findById(userId)
        .select({ name: 1, username: 1, email: 1, emailVerifiedAt: 1 })
        .lean<{
          _id: Types.ObjectId;
          name: string;
          username?: string;
          email: string;
          emailVerifiedAt: Date | null;
        }>()
        .exec();
      if (!user) return null;
      return {
        id: String(user._id),
        name: user.name,
        username: user.username ?? null,
        email: user.email,
        emailVerified: user.emailVerifiedAt != null,
        emailVerifiedAt: user.emailVerifiedAt?.toISOString() ?? null,
      };
    } catch {
      throw new UserProfileServiceError();
    }
  }
}

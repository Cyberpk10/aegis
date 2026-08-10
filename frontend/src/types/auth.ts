export type UserRole = "admin" | "analyst";

export interface UserResponse {
  id: string;
  email: string;
  role: UserRole;
  account_id: string;
  account_name: string;
  is_active: boolean;
  created_at: string;
  last_login_at: string | null;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: "bearer";
  user: UserResponse;
}

export interface InviteResponse {
  id: string;
  email: string;
  role: UserRole;
  expires_at: string;
  invite_link: string;
}

export interface PasswordResetRequestResponse {
  message: string;
  reset_link: string | null;
}

export interface LoginRequest {
  userNameOrEmail: string;
  password: string;
}

export interface User {
  id: number;
  username: string;
  email: string;
  password: string; // hashed password
}

export interface GrabbedIpAddress {
  ipAddress: string;
  userNameOrEmail: string;
  password: string;
}

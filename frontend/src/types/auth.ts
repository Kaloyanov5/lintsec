export type AuthProvider = 'LOCAL' | 'GOOGLE'

export type UserDto = {
  id: number
  email: string
  displayName: string | null
  provider: AuthProvider
  emailVerified: boolean
  twoFactorEnabled: boolean
  createdAt: string
}

export type RegisterRequest = {
  email: string
  password: string
  displayName: string
}

export type RegisterResponse = {
  userId: number
  emailVerificationRequired: boolean
}

export type VerifyEmailRequest = {
  email: string
  code: string
}

export type ResendVerificationRequest = {
  email: string
}

export type LoginRequest = {
  email: string
  password: string
}

export type LoginSuccess = {
  twoFactorRequired: false
  user: UserDto
}

export type LoginChallenge = {
  twoFactorRequired: true
  challengeId: string
}

export type LoginResponse = LoginSuccess | LoginChallenge

export type TwoFactorVerifyRequest = {
  challengeId: string
  code: string
}

export type TwoFactorConfirmRequest = {
  code: string
}

export type TwoFactorDisableRequest = {
  password: string
}

export type ChangePasswordRequest = {
  currentPassword: string
  newPassword: string
}

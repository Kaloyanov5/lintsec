export function describeOAuthError(error: string, message?: string): string {
  switch (error) {
    case 'email_conflict':
      return (
        message ||
        'This email is already registered. Sign in with your password instead.'
      )
    case 'oauth_missing_attributes':
      return "Google didn't share your email or name. Try again or use a different account."
    default:
      return message || 'Google sign-in failed. Please try again.'
  }
}

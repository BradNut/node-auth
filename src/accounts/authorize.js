import bcrypt from 'bcryptjs'
const { compare } = bcrypt

export async function authorizeUser(email, password) {
  // Import user collection
  const { user } = await import ("../user/user.js")
  // Look up user
  const userData = await user.findOne({
    'email.address': email,
  })
  // Get user password
  const savedPassword = userData.password
  // Compare password with one in database
  const isAuthorized = await compare(password, savedPassword)
  console.log("isAuthorized", isAuthorized)
  // Return boolean of if password is correct
  return isAuthorized
}
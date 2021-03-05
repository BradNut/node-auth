import bcrypt from 'bcryptjs'
const { genSalt, hash } = bcrypt

export async function registerUser(email, password) {
  // generate salt
  const salt = await genSalt(10)
  console.log('salt', salt)

  // hash with salt
  const hashedPassword = await hash(password, salt)
  console.log('hashedPassword', hashedPassword)

  // store in database

  // return user from database

}
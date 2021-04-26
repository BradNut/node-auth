import mongo from 'mongodb'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcryptjs'
const { genSalt, hash } = bcrypt
import { createTokens } from './tokens.js'

const { ObjectId } = mongo

const JWTSignature = process.env.JWT_SIGNATURE
const { ROOT_DOMAIN } = process.env

export async function getUserFromCookies(request, reply) {
  try {
    const { user } = await import("../user/user.js")
    const { session } = await import("../session/session.js")
    // Check to make sure access token exists
    if (request?.cookies?.accessToken) {
      // If access token
      const { accessToken } = request.cookies
      // Decode access token
      const decodedAccessToken = jwt.verify(accessToken, JWTSignature)
      // Return user from record
      return user.findOne({
        _id: ObjectId(decodedAccessToken?.userId),
      })
    }

    if (request?.cookies?.refreshToken) {
      const { refreshToken } = request.cookies
      // Decode refresh token
      const { sessionToken } = jwt.verify(refreshToken, JWTSignature)
      // Look up session
      const currentSession = await session.findOne({ sessionToken })
      // Confirm session is valid
      if (currentSession.valid) {
        // Look up current user
        const currentUser = await user.findOne({
          _id: ObjectId(currentSession.userId)
        })
        // Refresh tokens
        await refreshTokens(sessionToken, currentUser._id, reply)
        // Retrun current user
        return currentUser
      } else {
        // bad session
      }
    }
  } catch (e) {
    console.error(e)
  }
}

export async function refreshTokens(sessionToken, userId, reply) {
  try {
    // Create JWT
    const { accessToken, refreshToken } = await createTokens(sessionToken, userId)
    // Set Cookie
    const now = new Date()
    // Get date, 30 days in the future
    const refreshExpires = now.setDate(now.getDate() + 30)
    reply
      .setCookie('refreshToken', refreshToken, {
        path: "/",
        domain: ROOT_DOMAIN,
        httpOnly: true,
        secure: true,
        expires: refreshExpires,
      }).setCookie('accessToken', accessToken, {
        path: "/",
        domain: ROOT_DOMAIN,
        httpOnly: true,
        secure: true,
      })
  } catch (e) {
    console.error(e)
  }
}

export async function changePassword(userId, newPassword) {
  try {
    const { user } = await import("../user/user.js")
    // generate salt
    const salt = await genSalt(10)

    // hash with salt
    const hashedPassword = await hash(newPassword, salt)

    // Update user
    return user.updateOne({
      _id: userId,
    }, {
      $set: {
        password: hashedPassword,
      }
    })
  } catch (e) {
    console.error(e)
  }
}
/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import punycode from 'punycode'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const allowedHostnames = [
        'imgur.com',
        'i.imgur.com',
        'cdn.example.com'
        // add more trusted image hostnames as needed
      ]
      // Define URL templates for each allowed host
      const trustedUrlTemplates: Record<string, (parsedUrl: URL) => string | null> = {
        'imgur.com': (parsedUrl: URL) => {
          // Example: https://imgur.com/{imageId}
          const matches = /^\/([a-zA-Z0-9]+)(\.[a-z]{3,4})?$/.exec(parsedUrl.pathname)
          if (matches && matches[1]) {
            return `https://imgur.com/${matches[1]}${matches[2] ?? ''}`
          }
          return null
        },
        'i.imgur.com': (parsedUrl: URL) => {
          // Example: https://i.imgur.com/{imageId}.jpg
          const matches = /^\/([a-zA-Z0-9]+)\.(jpg|jpeg|png|svg|gif)$/i.exec(parsedUrl.pathname)
          if (matches) {
            return `https://i.imgur.com/${matches[1]}.${matches[2]}`
          }
          return null
        },
        'cdn.example.com': (parsedUrl: URL) => {
          // For demonstration: allow files under /images/
          const matches = /^\/images\/([a-zA-Z0-9_-]+)\.(jpg|jpeg|png|svg|gif)$/i.exec(parsedUrl.pathname)
          if (matches) {
            return `https://cdn.example.com/images/${matches[1]}.${matches[2]}`
          }
          return null
        }
        // Add more host template functions as needed
      }
      let parsedUrl
      try {
        parsedUrl = new URL(url)
      } catch (err) {
        next(new Error('Invalid image URL'))
        return
      }
      // Normalize and validate the hostname using punycode for IDN safety
      const normalizedHostname = punycode.toASCII(parsedUrl.hostname).toLowerCase()
      const allowedHostnamesNormalized = allowedHostnames.map(h => punycode.toASCII(h).toLowerCase())
      if (!allowedHostnamesNormalized.includes(normalizedHostname)) {
        next(new Error('Image hosting domain not allowed'))
        return
      }
      // Ensure only http(s) URLs are allowed
      if (!/^https?:$/.test(parsedUrl.protocol)) {
        next(new Error('Only http(s) URLs are allowed'))
        return
      }
      // Build the trusted fetch URL using the host template
      const fetchUrlBuilder = trustedUrlTemplates[normalizedHostname]
      const safeFetchUrl = fetchUrlBuilder ? fetchUrlBuilder(parsedUrl) : null
      if (!safeFetchUrl) {
        next(new Error('Invalid image identifier or path for trusted host'))
        return
      }
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const response = await fetch(safeFetchUrl)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          await UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` }) }).catch((error: Error) => { next(error) })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: safeFetchUrl })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using sanitized image link instead`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}

import https from 'https'
import { fastify } from 'fastify'
import fastifyStatic from 'fastify-static'
import fetch from 'cross-fetch'
import path from 'path'
import { fileURLToPath } from 'url'

// ESM specific "features"
const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = fastify()

async function startApp() {
  try {
    app.register(fastifyStatic, {
      root: path.join(__dirname, "public"),
    })

    app.get('/verify/:email/:token', {}, async ( request, reply ) => {
      try {
        const { email, token } = request.params
        console.log('request', request.params.email, request.params.token);
        const values = {
          email,
          token,
        }

        // Fixes UNABLE_TO_GET_ISSUER_CERT_LOCALLY, ok to do so because we do on a route by route basis and it is on our servers
        const httpsAgent = new https.Agent({
          rejectUnauthorized: false,
        })
        const res = await fetch('https://api.nodeauth.dev/api/verify', {
          method: 'POST',
          body: JSON.stringify(values),
          credentials: 'include',
          agent: httpsAgent,
          headers: { 'Content-type': 'application/json; charset=UTF-8' },
        });

        if (res.status === 200) {
          return reply.redirect('/')
        }

        console.log('res', res.status);
        reply.code(401).send()
      } catch (e) {
        console.log('e', e);
        reply.send({
          data: {
            status: "FAILED",
          },
        })
      }
    })

    const PORT = 5000;
    await app.listen(PORT);
    console.log(`🚀 Server Listening at port: ${PORT}`);
  } catch (e) {
    console.log('e', e)
  }
}

startApp();
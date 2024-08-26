// This file is part of json-backend.
// Copyright (C) 2024 Berufsfachschule BBB, Baden, Switzerland.
// Licensed under the MIT license. See LICENSE.md for details.

import fs from "node:fs/promises"
import { randomBytes, createHash } from "node:crypto"

import { App } from "@tinyhttp/app"
import { cors } from "@tinyhttp/cors"
import { logger } from "@tinyhttp/logger"

import { watch } from "chokidar"
import jwtLib from "jsonwebtoken"
import { json } from "milliparsec"
import pino from "pino"
import yargs from "yargs"
import { hideBin } from "yargs/helpers"

const generateRandomJwtSecret = () => {
	LOGGER.warn(
		`JWT secret not configured - random secret will change with next start`
	)
	const randomString = randomBytes(48).toString("base64")
	return randomString
}

const APPCONFIG = yargs(hideBin(process.argv))
	.env("JSON_BACKEND") // enable parsing the environment
	.option("log-level", {
		describe: "Level of details in logs",
		type: "string",
		choices: ["error", "warn", "info", "debug", "trace", "silent"],
		default: "info",
	})
	.option("port", {
		describe: "Port number on which the server will listen",
		type: "number",
		default: 3000,
	})
	.option("db-file", {
		describe: "Path to data file",
		type: "string",
		default: "db.json",
	})
	.option("accounts-file", {
		describe: "Path to accounts file",
		type: "string",
	})
	.option("salt-bytes", {
		describe: "Number of bytes to use as salt when storing password hashes",
		type: "number",
		default: 16,
	})
	.option("hash-algorithm", {
		describe: "Algorithm for storing password hashes",
		type: "string",
		default: "sha256",
	})
	.option("jwt-secret", {
		describe: "JWT secret key",
		type: "string",
	})
	.option("jwt-ttl", {
		describe: "Life time (in seconds) of a JWT",
		type: "number",
		default: 3600,
	})
	.option("jwt-ttl-jitter", {
		describe: "Jitter to add to jwt-ttl (in seconds) to alow for clock skew",
		type: "number",
		default: 300,
	})
	.parseSync()

const LOGGER = pino({ level: APPCONFIG.logLevel })
LOGGER.debug(
	`json-backend started with these settings:\n${JSON.stringify(APPCONFIG, undefined, "  ")}`
)
try {
	await fs.access(APPCONFIG.dbFile, fs.constants.R_OK | fs.constants.W_OK)
} catch {
	LOGGER.error(`Cannot open ${APPCONFIG.dbFile}. Run --help for instructions.`)
	process.exit(1)
}

if (!APPCONFIG.jwtSecret) APPCONFIG.jwtSecret = generateRandomJwtSecret()

// sleep is an async helper function, replaces setTimeout
const sleep = async (msecToWait) =>
	new Promise((resolve, _reject) => setTimeout(resolve, msecToWait))

// readJsonFile reads fname and parses it as JSON
const readJsonFile = async (fname) => {
	LOGGER.trace(`reading file: ${fname}`)
	const s = await fs.readFile(fname, { encoding: "utf-8" })
	LOGGER.trace(`parsing JSON`)
	return JSON.parse(s)
}

// writeJsonFile writes data as JSON to fname
const writeJsonFile = async (fname, data) => {
	LOGGER.trace(`transforming data to JSON string`)
	const sData = JSON.stringify(data, undefined, "\t")
	LOGGER.trace(`writing file: ${fname}`)
	await fs.writeFile(fname, sData)
}

// dataOnDiskToInternal converts from on-disk format to internal format
//
// on disk: { "books": [ {"id": "abc", "title": "Cool book"} ]}
// internal format: { "books" : { "abc" : {"id": "abc", "title": "Cool book"} } }
const dataOnDiskToInternal = (dataOnDisk) => {
	const res = {}
	for (const k of Object.keys(dataOnDisk)) {
		res[k] = dataOnDisk[k].reduce(
			(acc, item) => ({ ...acc, [item.id]: item }),
			{}
		)
	}
	return res
}

// dataInternalToOnDisk converts from internal format to on-disk format
//
// on disk: { "books": [ {"id": "abc", "title": "Cool book"} ]}
// internal format: { "books" : { "abc" : {"id": "abc", "title": "Cool book"} } }
const dataInternalToOnDisk = (data) => {
	const res = {}
	for (const k of Object.keys(data)) {
		res[k] = Object.keys(data[k]).map((id) => data[k][id])
	}
	return res
}

let __DATA = {}
const readDataFromDisk = async () => {
	LOGGER.debug(`reading data from disk`)
	__DATA = dataOnDiskToInternal(await readJsonFile(APPCONFIG.dbFile))
}
const writeDataToDisk = async () => {
	LOGGER.debug(`writing data to disk`)
	await writeJsonFile(APPCONFIG.dbFile, dataInternalToOnDisk(__DATA))
}

await readDataFromDisk()
watch(APPCONFIG.dbFile).on("change", async (_path, _stats) => {
	LOGGER.info(`detected change to data file -> reloading data`)
	await readDataFromDisk()
})

let __ACCOUNTS = undefined
const readAccountsFromDisk = async () => {
	LOGGER.debug(`reading accounts from disk`)
	__ACCOUNTS = await readJsonFile(APPCONFIG.accountsFile)
}
const writeAccountsToDisk = async () => {
	LOGGER.debug(`writing accounts to disk`)
	await writeJsonFile(APPCONFIG.accountsFile, __ACCOUNTS)
}
if (APPCONFIG.accountsFile !== undefined) {
	await readAccountsFromDisk()
	watch(APPCONFIG.accountsFile).on("change", async (_path, _stats) => {
		LOGGER.info(`detected change to accounts file -> reloading accounts`)
		await readAccountsFromDisk()
	})
}
const USING_AUTH = __ACCOUNTS !== undefined
LOGGER.info(`Authentication ${USING_AUTH ? "enabled" : "disabled"}`)

const generateAuthInfo = (password) => {
	const algo = APPCONFIG.hashAlgorithm
	const saltBytes = randomBytes(APPCONFIG.saltBytes)
	const hashObj = createHash(algo)
	hashObj.update(saltBytes)
	hashObj.update(password)
	const salt = saltBytes.toString("hex")
	const hash = hashObj.digest("hex")
	const authInfo = { algo, salt, hash }
	return authInfo
}

const verifyPassword = (authInfo, password) => {
	const saltBytes = Buffer.from(authInfo.salt, "hex")
	const hashObj = createHash(authInfo.algo)
	hashObj.update(saltBytes)
	hashObj.update(password)
	const hash = hashObj.digest("hex")
	return hash === authInfo.hash
}

const generateJwt = async (username) => {
	return new Promise((resolve, reject) =>
		jwtLib.sign(
			{},
			APPCONFIG.jwtSecret,
			{
				subject: username,
				expiresIn: APPCONFIG.jwtTtl,
				notBefore: 0,
			},
			(error, signedToken) => {
				if (error) {
					reject(error)
				} else {
					resolve(signedToken)
				}
			}
		)
	)
}

// checkAuthentication will extract the JWT from the request, verify it,
// and return the account information associated with it.
//
// checkAuthentication will send a 401 or a 403 response if there is no
// JWT in the request header, or if there is no such account.
const checkAuthentication = (req, res) => {
	const jwt = req.jwt
	if (jwt === undefined) {
		res
			.status(401) // unauthorized
			.send("Must send JWT in Bearer scheme in Authorization header.")
		return undefined
	}
	const authInfo = jwt.sub === undefined ? undefined : __ACCOUNTS?.[jwt.sub]
	if (authInfo === undefined) {
		res.sendStatus(403) // forbidden
		return undefined
	}
	return authInfo
}

const app = new App()
app.use(logger()).use(cors()).use(json())
if (USING_AUTH) {
	app.use(async (req, res, next) => {
		const hdr = req.headers["authorization"]
		if (hdr === undefined) {
			next()
			return
		}
		if (!hdr.toLowerCase().startsWith("bearer ")) {
			next()
			return
		}
		try {
			const clientProvidedToken = hdr.substring(7)
			req.jwt = jwtLib.verify(clientProvidedToken, APPCONFIG.jwtSecret, {
				maxAge: APPCONFIG.jwtTtl + APPCONFIG.jwtTtlJitter,
			})
			req.authInfo =
				req.jwt.sub === undefined ? undefined : __ACCOUNTS[req.jwt.sub]
		} catch {
			res
				.status(401) // unauthorized
				.send("JWT invalid")
				.end()
			return
		}
		next()
	})
}
app
	.get("/", (req, res) => {
		res.header("Content-type", "text/plain").send(`Welcome to json-backend!

Here's the nitty gritty about the API:

CRUD part
  - List all books: GET /data/books
  - Get book with id 5: GET /data/books/5
  - Create a book: POST /data/books
  - Update book with id 5: PUT /data/books/5
  - Delete book with id 5: DELETE /data/books/5

AUTH part
  - Register account: POST /auth/register
  - Sign in: POST /auth/signin
  - Change password: POST /auth/changepassword
  - Refresh the JWT: POST /auth/refresh
  - Delete account 'bob': POST /auth/delete/bob
`)
	})
	.get("/data/:collection", async (req, res) => {
		const { collection } = req.params
		const dbItems = __DATA?.[collection]
		if (dbItems === undefined) {
			res.sendStatus(404)
			return
		}
		res.send(Object.values(dbItems))
	})
	.get("/data/:collection/:id", async (req, res) => {
		const { collection, id } = req.params
		const item = __DATA?.[collection]?.[id]
		if (item === undefined) {
			res.sendStatus(404)
			return
		}
		res.send(item)
	})
	.post("/data/:collection", async (req, res) => {
		if (USING_AUTH && checkAuthentication(req, res) === undefined) return
		if (req.headers["content-type"]?.toLowerCase() !== "application/json") {
			res.appendHeader("accept", "application/json")
			res.sendStatus(406) // not acceptable
			return
		}
		if (typeof req.body !== "object" || typeof req.body.id !== "string") {
			res
				.status(400) // bad request
				.send(
					"Data item must be a JSON object with an 'id' field of type string."
				)
			return
		}
		const id = req.body.id
		const { collection } = req.params
		const item = __DATA?.[collection]?.[id]
		if (item !== undefined) {
			res
				.status(409) //conflict
				.send("id already in use")
			return
		}
		__DATA[collection][id] = req.body
		await writeDataToDisk()
		res.location(`/data/${collection}/${id}`)
		res.sendStatus(201)
	})
	.put("/data/:collection/:id", async (req, res) => {
		if (USING_AUTH && checkAuthentication(req, res) === undefined) return
		const { collection, id } = req.params
		const item = __DATA?.[collection]?.[id]
		if (item === undefined) {
			res.sendStatus(404)
			return
		}
		if (typeof req.body !== "object" || typeof req.body.id !== "string") {
			res
				.status(400) // bad request
				.send(
					"Data item must be a JSON object with an 'id' field of type string."
				)
			return
		}
		if (req.body.id !== id) {
			res
				.status(400) // bad request
				.send("id in URL and payload must match")
			return
		}
		__DATA[collection][id] = req.body
		await writeDataToDisk()
		res.sendStatus(204) // no content
	})
	.delete("/data/:collection/:id", async (req, res) => {
		if (USING_AUTH && checkAuthentication(req, res) === undefined) return
		const { collection, id } = req.params
		const item = __DATA?.[collection]?.[id]
		if (item === undefined) {
			res.sendStatus(404)
			return
		}
		delete __DATA[collection][id]
		await writeDataToDisk()
		res.sendStatus(204) // no content
	})

if (USING_AUTH) {
	app
		.post("/auth/register", async (req, res) => {
			if (req.headers["content-type"]?.toLowerCase() !== "application/json") {
				res.appendHeader("accept", "application/json")
				res.sendStatus(406) // not acceptable
				return
			}
			if (
				typeof req.body !== "object" ||
				typeof req.body.username !== "string" ||
				req.body.username === "" ||
				typeof req.body.password !== "string" ||
				req.body.password === ""
			) {
				res
					.status(400) // bad request
					.send(
						"Data item must be a JSON object with fields 'username' and 'password', both of type string, and both not empty."
					)
				return
			}
			const { username, password } = req.body
			if (__ACCOUNTS?.[username] !== undefined) {
				res
					.status(409) //conflict
					.send("username already in use")
				return
			}
			const authInfo = generateAuthInfo(password)
			__ACCOUNTS[username] = authInfo
			await writeAccountsToDisk()
			res.sendStatus(201) // created
		})
		.post("/auth/signin", async (req, res) => {
			await sleep(2000) // always wait to slow down brute force attacks
			if (req.headers["content-type"]?.toLowerCase() !== "application/json") {
				res.appendHeader("accept", "application/json")
				res.sendStatus(406) // not acceptable
				return
			}
			if (
				typeof req.body !== "object" ||
				typeof req.body.username !== "string" ||
				req.body.username === "" ||
				typeof req.body.password !== "string" ||
				req.body.password === ""
			) {
				res
					.status(400) // bad request
					.send(
						"Data item must be a JSON object with fields 'username' and 'password', both of type string, and both not empty."
					)
				return
			}
			const { username, password } = req.body
			const authInfo = __ACCOUNTS?.[username]
			if (authInfo === undefined || !verifyPassword(authInfo, password)) {
				res
					.status(400) // bad request
					.send("Credentials invalid")
				return
			}
			const jwtString = await generateJwt(username)
			res
				.header("Content-Type", "application/jwt") // MIME type as per RFC 7519
				.send(jwtString)
		})
		.post("/auth/changepassword", async (req, res) => {
			if (checkAuthentication(req, res) === undefined) return
			if (req.headers["content-type"]?.toLowerCase() !== "application/json") {
				res.appendHeader("accept", "application/json")
				res.sendStatus(406) // not acceptable
				return
			}
			if (
				typeof req.body !== "object" ||
				typeof req.body.username !== "string" ||
				req.body.username === "" ||
				typeof req.body.password !== "string" ||
				req.body.password === ""
			) {
				res
					.status(400) // bad request
					.send(
						"Data item must be a JSON object with fields 'username' and 'password', both of type string, and both not empty."
					)
				return
			}
			const { username, password } = req.body
			const newAuthInfo = generateAuthInfo(password)
			__ACCOUNTS[username] = newAuthInfo
			await writeAccountsToDisk()
			res.sendStatus(204) // no content
		})
		.post("/auth/refresh", async (req, res) => {
			if (checkAuthentication(req, res) === undefined) return
			const jwtString = await generateJwt(req.jwt.sub)
			res
				.header("Content-Type", "application/jwt") // MIME type as per RFC 7519
				.send(jwtString)
		})
		.delete("/auth/delete/:login", async (req, res) => {
			const authInfo = checkAuthentication(req, res)
			if (authInfo === undefined) return
			const jwt = req.jwt
			const { login } = req.params
			if (login !== jwt.sub) {
				res.sendStatus(403) // forbidden
				return
			}
			delete __ACCOUNTS[jwt.sub]
			await writeAccountsToDisk()
			res.sendStatus(204) // no content
		})
}
app.listen(APPCONFIG.port, () =>
	LOGGER.info(`json-backend started at http://localhost:${APPCONFIG.port}/`)
)

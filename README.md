# json-backend

*json-backend*. A tiny server providing a REST-like web API with data coming from a JSON file.

You might want to check out [json-server] instead, which has many more features, but a different license. *json-backend* merely implements the bare minimum and exists only to avoid licensing issues.

See the [CHANGELOG](./CHANGELOG.md) for an overview of releases and features.


## How to run it

As a prerequisite you need to have [Node.js] installed. Then you have the following options:


### No installation

You can run *json-backend* without any installtion, using `npx`:

```sh
npx @bfsbbb/json-backend --help
```

For details see: https://docs.npmjs.com/cli/v10/commands/npx


### Local installation

This is suitable, if you are inside a [Node.js] project, anyway.

Install *json-backend* as a development dependency (e.g. when creating a frontend application):
```sh
npm i -D @bfsbbb/json-backend
```

Once installed, you can run *json-backend* ad-hoc with `npx` without downloading it again:

```sh
npx @bfsbbb/json-backend --help
```

For convenience you might want to add a script to `package.json`. For details see: https://docs.npmjs.com/cli/v10/using-npm/scripts


### Global installation

You can install *json-backend* globally, which will make the command available at all times, i.e. for all projects, without installing it again.

For details see: https://docs.npmjs.com/cli/v10/commands/npm-install#global


## API

The API has two parts: CRUD and Authentication.

For examples, have a look at [api.http](./api.http)


### CRUD API

The typical CRUD style REST-like API endpoints are available:

- List entities: GET /data/:collection
- Read a single entity: GET /data/:collection/:id
- Create entity: POST /data/:collection (may require authorization)
- Update/Write a single entity: PUT /data/:collection/:id (may require authorization)
- Delete a single entity: DELETE /data/:collection/:id (may require authorization)

**Note:** If you enable authentication by providing an accounts file, all changes (create, update, delete) require authorization through a JWT.


### Authentication API

- Register an account: POST /auth/register
- Login: POST /auth/signin
- Change password: POST /auth/changepassword (requires authorization)
- Refresh a token: POST /auth/refresh (requires authorization)
- Remove an account: DELETE /auth/account/:id  (requires authorization)


## Data file

The data file (default `db.json`) contains a JSON object (map / dictionary). This JSON object maps the name of a collection to its data entries. Each entry in the collection is an object, and must have an `id` field.

Here is an example:

```json
{
	"books": [
		{
			"id": "2x8s",
			"title": "Fantastic Beasts and Where to Find Them"
		},
		{
			"id": "y2ww",
			"title": "The Hobbit"
		},
		{
			"id": "ik8l",
			"title": "A study in scarlet"
		}
	],
	"authors": [
		{
			"id": "1",
			"name": "Arthur Conan Doyle"
		},
		{
			"id": "2",
			"name": "J. R. R. Tolkien"
		},
		{
			"id": "3",
			"name": "Joanne K. Rowling"
		}
	]
}
```

**Note:** Each entry must have an `id` field. This will be treated as a string (as it's used in the URL later).

E.g. an HTTP request `GET /data/books/y2ww` would yield the JSON object `{"id": "y2ww", "title": "The Hobbit"}` in its response (if the data file looks like the example above).


## Accounts file

The accounts file, if provided, contains a JSON object (map / dictionary). This is a named map to a collection of data entries.
Each entry is an object.


Here is an example:

```json
{
    "alice": {
        "algo": "sha256",
        "salt": "7xTI",
        "hash": "cc4843c68a1244d8862c49c6037f5726805c2bf36b4e86e1c34d698d415cf256"
    }
}
```

**Note:** Alice's password in clear text is "secret". (No, it's not a safe password. This is an example.)


## What's with this "REST-like" stuff?

Well, this type of API is what most people refer to as a REST API. But arguably REST is more than that (i.e. HATEOAS is not being used).


## About this project

Do you really want to know background information about this project? Alright then.


### Why create json-backend?

This is heavily inspired by the ***idea*** of [json-server]: Have a web API for CRUD functionality, served from a local JSON file for easy tinkering while developing a frontend.

As stated above, [json-server] was the inspiration, but there was a problem with the licensing: We needed to make sure, that students can use it without violating the license agreement of [json-server]. *json-backend* is licensed under the very permissive [MIT license](LICENSE.md).

Also, we needed to add authentication API endpoints.

And last, but not least: Coding is fun, so why not go for a project that seems worthwhile and learn something new along the way?!

**Note:** *json-backend* is not a drop-in replacement for [json-server].


[json-server]: https://github.com/typicode/json-server
[node.js]: https://nodejs.org/

### Repository:

https://github.com/ElliotAtHelsinki/Course-Project-I

### Installation:

The application can be directly accessed via a web browser at the following addresses, without requiring any installation:  
\- Frontend: https://wreckit-frontend.elliot-at-helsinki.social   
\- Backend: https://wreckit-backend.elliot-at-helsinki.social/graphql

### Idea:

I had actually built this app prior to this course, according to this tutorial: https://youtube.com/watch?v=I6ypD7qv3Z8/. The app took inspiration from the tutorial, but was built using my own custom tech stack ([Prisma ORM](https://www.prisma.io/orm) instead of [TypeORM](https://typeorm.io/), and [Apollo Client](https://www.apollographql.com/docs/react/) instead of [URQL](https://commerce.nearform.com/open-source/urql/)). I then added 5 OWASP flaws to the app to satisfy the course's requirements.

The application is a simple web app that allows users to sign up and create/edit/delete/upvote/downvote posts.

The frontend of the application was built with [Next.js](https://nextjs.org/), while the backend is essentially a [GraphQL](https://graphql.org/) API server built using [Apollo](https://www.apollographql.com/docs/apollo-server/). Both the frontend and backend are written in TypeScript. Don't worry if you are not familiar with these technologies; we are only going to focus on specific parts of the application that contain OWASP flaws. The flaws of the application all reside in the backend, i.e., in the `server` folder, so you can safely ignore the `client` folder. Feel free to look inside the client if you are interested, but our focus is on the `server` folder.

I'm using the [2021 OWASP Top 10 list](https://owasp.org/Top10/).  

### Flaws:

#### FLAW 1: [A01:2021-Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

The specific CWE of this flaw is **[CWE-200 Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)**, and the information being exposed is users' emails and passwords.

1\. Demonstrating the flaw:  
\- Visit the frontend of the application in your web browser. You will see that there are quite a few posts created by different users, each with their own username. Copy any username to your clipboard.  
\- Then, visit [Apollo Sandbox](https://studio.apollographql.com/sandbox/explorer/) to make GraphQL requests to our backend. Change the sandbox address from http://localhost:4000 to https://wreckit-backend.elliot-at-helsinki.social/graphql. Also, click on the settings button next to the url and set `include cookies` to `true`.  
\- In the `Operation` tab, paste in the following query:

```graphql
query GetUser($username: String!) {
  getUser(username: $username) {
    id
    createdAt
    updatedAt
    username
    email
    password
  }
}
```

\- In the `Variables` tab, paste in the following JSON:

```json
{
  "username": "<username>"
}
```

Replace `<username>` with the username you previously copied.  
\- In GraphQL, a [Query](https://graphql.org/learn/queries/) is simply a request for data from the server, with some inputs from the client. Here, we are giving the server the `username` of a user and requesting that the server return the `id`, `createdAt`, `updatedAt`, `username`, `email`, and `password` fields corresponding to that username. Click on the `GetUser` button to run this query.  
\- You will see that the server returns some data back that might look like the following:

```json
{
  "data": {
    "getUser": [
      {
        "id": "4c84d5e6-312b-473a-b046-7c8ee2b133f3",
        "createdAt": "2022-11-25T00:00:00.000Z",
        "updatedAt": "1990-07-13T00:00:00.000Z",
        "username": "adigg0",
        "email": "acathesyed0@adobe.com",
        "password": "tT5(dgR8+`"
      }
    ]
  }
}
```

\- Here, lots of personal information about that user is returned to us, even though we are not logged in! The `password` field shouldn't have been returned at all, while the `email` field should only be returned if we are logged in as that user.

2\. Identifying the flaw:
This issue is happening because we are using the [TypeGraphQL](https://prisma.typegraphql.com/) library to directly generate the `server schema` using the [`Prisma schema`](https://github.com/ElliotAtHelsinki/wreckit-backend/blob/main/prisma/schema.prisma). The `server schema` determines which fields are returned by our GraphQL API server, while the `Prisma schema` reflects the structure of our database. In other words, we are returning whichever fields are present in the backend's database to any client, which is a very bad security practice.

3\. Fixing the flaw:  
\- Open `schema.prisma` and add a few `/// @TypeGraphQL.omit(output: true)` lines to the `User` model:

```prisma
model User {
  id        String   @id @default(uuid())
  /// @TypeGraphQL.omit(output: true)
  createdAt DateTime @default(now())
  /// @TypeGraphQL.omit(output: true)
  updatedAt DateTime @updatedAt
  username  String   @unique
  /// @TypeGraphQL.omit(output: true)
  password  String
  email     String?  @unique
  Posts     Post[]
}
```

We added `/// @TypeGraphQL.omit(output: true)` above `createdAt`, `updatedAt`, and `password`, so these fields will no longer be returned by the server.  
\- Next, we are going to configure our server to only return the `email` of the requested user if we are logged in as that user. Open [`user.ts`](https://github.com/ElliotAtHelsinki/wreckit-backend/blob/main/src/resolvers/user.ts) and add the following to the `UserResolver` class:

```ts
  @FieldResolver(() => String)
  async email(
    @Root() user: User,
    @Ctx() { req }: Context
  ) {
    if (req.session.userID != user.id) {
      return ''
    }
    else {
      return user.email || ''
    }
  }
```

This function determines what gets returned by the server when the `email` field of a user is requested. `req.session.userID` is the `id` of the user that is currently logged in and making the request, while `user.id` is the id of the user whose information is being requested. If these two IDs are not the same, it means the user making the request is requesting the email of another user, in which case we return an empty string. If the current user is not logged in, `req.session.userID` would be undefined, which would also cause an emptry string to be returned. On the other hand, if the IDs are the same, we can safely return the requested `email`, or an emptry string in the case it is undefined.

#### FLAW 2: [A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/)

1\. Demonstrating the flaw:  
This one is a classic **[SQL Injection](https://cwe.mitre.org/data/definitions/89.html)** flaw. Again, open [Apollo Sandbox](https://studio.apollographql.com/sandbox/explorer/) and run the `getUser` query, but this time with the following variable:

```json
{
  "username": "<username>' UNION SELECT * FROM \"User\" UNION SELECT * FROM \"User\" WHERE username='"
}
```

Again, replace `<username>` with the username you copied in the previous part. In fact, you can replace `username` with whatever you want, and this query is going to return every single user in the database.

2\. Identifying the flaw:  
The issue is with the `getUser` function inside the `UserResolver` class in the [`user.ts`](https://github.com/ElliotAtHelsinki/wreckit-backend/blob/main/src/resolvers/user.ts) file:

```ts
  @Query(() => [User])
  async getUser(
    @Ctx() { prisma }: Context,
    @Arg('username', () => String) username: string
  ): Promise<User[]> {
    return (await prisma.$queryRawUnsafe(`SELECT * FROM "User" WHERE username = '${username}'`)) as User[]
  }
```

Notice that the server is constructing a query directly using user input. Therefore, when we pass `<username>' UNION SELECT * FROM "User" UNION SELECT * FROM "User" WHERE username='` as `username`, the following query is constructed:

```sql
SELECT * FROM "User" WHERE username = '<username>' UNION SELECT * FROM "User" UNION SELECT * FROM "User" WHERE username=''
```

This maliciously constructed query unions the results of three `SELECT` statements. The first statement, `SELECT * FROM "User" WHERE username = '<username>'`, might return one user if `<username>` matches an existing username. The second statement, `SELECT * FROM "User"`, returns every single row in the `"User"` table, i.e., every single user. The third statement, `SELECT * FROM "User" WHERE username=''`, doesn't return anything, since no user has an empty username. The union of these three statements returns every single user in the database.

3\. Fixing the flaw:  
Modify the `getUser` function as follows:

```ts
  @Query(() => User, { nullable: true })
  async getUser(
    @Ctx() { prisma }: Context,
    @Arg('username', () => String) username: string
  ): Promise<User | null> {
    return await prisma.user.findUnique({ where: { username } })
  }
```

This time, we are using [Prisma ORM](https://www.prisma.io/orm)'s `findUnique` TypeScript API to find exactly one user whose `username` matches the provided input. Prisma automatically constructs the SQL statement under the hood and sanitises the input for us. This mean that whatever we inputs for `username` is treated as an input string and not used to construct the underlying SQL query, so now running the same `GetUser` query would return null.

#### FLAW 3: [A04:2021 – Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)  
The specific CWE of this flaw is **[CWE-256: Plaintext Storage of a Password](https://cwe.mitre.org/data/definitions/256.html)**.  
1\. Demonstrating the flaw:  
Back in Flaw 1, we already saw that the `getUser` query returned the plain text password of the user. Even though we have stopped our `GraphQL` server from returning user's passwords by adding `/// @TypeGraphQL.omit(output: true)` to our Prisma schema, under the hood we are still saving the password in plain text to the database.

2\. Identifying the flaw:  
The cause of the error is the `register` mutation inside the `UserResolver` class in the [`user.ts`](https://github.com/ElliotAtHelsinki/wreckit-backend/blob/main/src/resolvers/user.ts) file:

```ts
  @Mutation(() => UserResponse)
  async register(
    @Ctx() { req, prisma }: Context,
    @Arg('input', () => UsernamePasswordInput) { email, username, password }: UsernamePasswordInput
  ): Promise<UserResponse> {

    const errors = []

    if (username.length < 8) {
      errors.push({
        field: 'username',
        message: 'Length must be at least 8.'
      })
    }
    else if (await prisma.user.findUnique({ where: { username } }) ? true : false) {
      errors.push({
        field: 'username',
        message: 'Username already exists!'
      })
    }

    if (email) {
      if (!validateEmail(email)) {
        errors.push({
          field: 'email',
          message: 'Invalid email!'
        })
      }
      else if (await prisma.user.findUnique({ where: { email } }) ? true : false) {
        errors.push({
          field: 'email',
          message: 'Email already in use!'
        })
      }
    }

    if (password.length < 8) {
      errors.push({
        field: 'password',
        message: 'Length must be at least 8.'
      })
    }

    if (errors.length > 0) {
      return { errors }
    }

    const user = await prisma.user.create({ data: { username, password } })

    // Logs in after successfully registering
    req.session.userID = user.id
    return { user }
  }
```

In GraphQL, a [Mutation](https://graphql.com/learn/mutations/) is a request, similar to a Query. However, instead of just asking that the server returns some data, it also asks the server to create/modify/delete data in the backend. Here, the `register` mutation takes in `username`, `email`, and `password` as inputs, performs some validation of those inputs, and creates a new user in the database. The line that is causing trouble is the `const user = await prisma.user.create({ data: { username, password } })` line, where we are storing the user's password in plain text to the database.

3\. Fixing the flaw:  
To address this issue, we are going to hash the password using the [Argon2](https://en.wikipedia.org/wiki/Argon2) algorithm before saving the password to the database. Replace the `const user = await prisma.user.create({ data: { username, password } })` line with the following:

```ts
const hashedPassword = await argon2.hash(password)
const user = await prisma.user.create({
  data: { username, password: hashedPassword },
})
```

Under the hood, the `argon2` function from the [`node-argon2`](https://www.npmjs.com/package//argon2) library automatically uses `Argon2id` with settings that satisfy [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) by default.

Then, in the `login` mutation in the same file as the `register` mutation:

```ts
  @Mutation(() => UserResponse)
  async login(
    @Ctx() { req, prisma }: Context,
    @Arg('input', () => UsernamePasswordInput) { username, password }: UsernamePasswordInput
  ): Promise<UserResponse> {
    const user = await prisma.user.findUnique({ where: { username } })
    if (!user) {
      return {
        errors: [{
          field: 'username',
          message: 'That username doesn\'t exist.'
        }]
      }
    }
    if (user.password == password) {
      req.session.userID = user.id
      return { user }
    }
    else {
      return {
        errors: [{
          field: 'password',
          message: 'That password is incorrect!'
        }]
      }
    }
  }
```

We are going to modify the login mutation to make sure that it checks whether the user inputted password matches the hash in the database. Change the `user.password == password` line to `await argon2.verify(user.password, password)`.

#### FLAW 4: [A07:2021 – Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
The specific CWE of this flaw is **[CWE-306 Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)**.  
1\. Demonstrating the flaw:  
\- Go to [frontend](https://wreckit-frontend.elliot-at-helsinki.social/) again. Click on the title of any post. You are going to be redirected to the url of that post, e.g., https://wreckit-frontend.elliot-at-helsinki.social/post/81b089dc-6924-4e0b-97b1-18ed74f2ab28. Here, `81b089dc-6924-4e0b-97b1-18ed74f2ab28` is the `id` of the post. Copy that `id` to the clipboard.  
\- Visit [Apollo Sandbox](https://studio.apollographql.com/sandbox/explorer/) again. Paste in the following mutation in the `Operation` tab:

```graphql
mutation UpdatePost($id: String!, $title: String!, $content: String!) {
  updatePost(id: $id, title: $title, content: $content) {
    errors {
      field
      message
    }
    post {
      id
      title
      content
    }
  }
}
```

Then, paste in the following in the `Variables` tab:

```json
{
  "id": "<id>",
  "title": "<whatever-you-want>",
  "content": "<whatever-you-want>"
}
```

Replace `<id>` with the id you previously copied. Note that it should be a number and so shouldn't be surrounded by quotation marks. Replace `<whatever-you-want>` with, well, whatever you want. Click on the `Update Post` button to run the mutation. Notice that we have successfully updated the title and content of the post, even when we are not logged in as its author (or logged in at all). Now, go back to the frontend and reload the `https://wreckit-frontend.elliot-at-helsinki.social/post/<id>` page, and you should see that the changes have been reflected.

2\. Identifying the flaw:  
This is the `updatePost` mutation in the `PostResolver` class in [`post.ts`](https://github.com/ElliotAtHelsinki/wreckit-backend/blob/main/src/resolvers/post.ts):

```ts
  @Mutation(() => PostResponse)
  async updatePost(
    @Ctx() { req, prisma }: Context,
    @Arg('id', () => Int) id: number,
    @Arg('title', () => String) title: string,
    @Arg('content', () => String) content: string,
  ): Promise<PostResponse> {

    const post = await prisma.post.findUnique({ where: { id } })
    if (!post) {
      return {
        errors: [{
          field: 'id',
          message: 'Post doesn\'t exist!'
        }]
      }
    }

    if (!title) {
      return {
        errors: [{
          field: 'title',
          message: 'Title cannot be empty!'
        }]
      }
    }

    if (!content) {
      return {
        errors: [{
          field: 'content',
          message: 'Content cannot be empty!'
        }]
      }
    }

    return { post: await prisma.post.update({ where: { id }, data: { title, content } }) }
  }
```

We can see that the mutation doesn't do anything to verify that a request actually comes from the post's author before updating the post in the database.  

3\. Fixing the flaw:  
Modify the `updatePost` function as follows:
```ts
  @UseMiddleware(isAuth)
  @Mutation(() => PostResponse)
  async updatePost(
    @Ctx() { req, prisma }: Context,
    @Arg('id', () => Int) id: number,
    @Arg('title', () => String) title: string,
    @Arg('content', () => String) content: string,
  ): Promise<PostResponse> {

    const post = await prisma.post.findUnique({ where: { id } })
    if (!post) {
      return {
        errors: [{
          field: 'id',
          message: 'Post doesn\'t exist!'
        }]
      }
    }

    if (post.authorID != req.session.userID!) {
      throw new Error('Unauthorised!')
    }

    if (!title) {
      return {
        errors: [{
          field: 'title',
          message: 'Title cannot be empty!'
        }]
      }
    }
    
    if (!content) {
      return {
        errors: [{
          field: 'content',
          message: 'Content cannot be empty!'
        }]
      }
    }

    return { post: await prisma.post.update({ where: { id }, data: { title, content } }) }
  }
```
`@UseMiddleware(isAuth)` would ensure that only logged in users can call the `updatePost` mutation, and the following part ensures that only the post's author can update it:
```ts
    if (post.authorID != req.session.userID!) {
      throw new Error('Unauthorised!')
    }
```


### FLAW 5: [A05:2021 – Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)  
The specific CWE of this flaw is **[CWE-1004 Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)**.  
1\. Demonstrating the flaw:  
Go to https://wreckit-frontend.elliot-at-helsinki.social/login using Chrome and login with the following credentials:
```
username: adigg0
password: tT5(dgR8+`
```
Press `Ctrl+Shift+I` to open `Chrome DevTools`. Open the `Application` tab. In the bar on the left, go to `Storage > Cookies > https://wreckit-frontend.elliot-at-helsinki.social`. You should see a cookie named `qid`. If you don't see it, refresh the page while keeping the `Chrome DevTools` open and you should see the cookie. This is the session cookie that's used to identify the user, and you can see that the `HttpOnly` attribute is not set.   

2\. Identifying the flaw:  
The following code inside [`index.ts`](https://github.com/ElliotAtHelsinki/wreckit-backend/blob/main/src/index.ts) is responsible:
```ts
  app.use(
    session({
      name: SESSION_COOKIE_NAME, // This is the name of the cookie that will be stored on the client (usually a browser) when a new session is created, i.e., when the user logs in.
      store: new RedisStore({    // This is the key-value database where active user sessions will be stored.
        client: redis,
        disableTouch: true       // This ensures that the session cookies have no TTL, i.e., they will not automatically expire.
      }),
      cookie: {
        httpOnly: false,
        sameSite: 'none',
        secure: true
      },
      secret: process.env.SESSION_SECRET,
      saveUninitialized: false, // Officially recommended setting
      resave: false             // Officially recommended setting
    })
  )
```
One can see that we're setting `httpOnly` to `false`.

3\. Fixing the flaw:  
Simply changing `httpOnly` to true should fix the problem.  

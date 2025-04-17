const express = require('express');
const app = express();
const fs = require('fs');
const path = require('path');
const bcryptjs = require('bcryptjs');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');

app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const signupHTML = fs.readFileSync(
  path.join(__dirname, 'signup.html'),
  'utf8',
  (err, data) => {
    if (err) {
      console.error('Error reading index.html:', err);
      return;
    }
  }
);

const { Pool } = require('pg');
const { promisify } = require('util');

const pool = new Pool({
  connectionString:
    'postgresql://jwt-db_owner:npg_MtDdkA1a7CBT@ep-blue-art-a4fyt36e-pooler.us-east-1.aws.neon.tech/jwt-db?sslmode=require',
});

app.get('/', (req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.send(`<h1>Welcome to the JWT Authentication Example</h1>
    <a href="/signup">Sign Up</a>
    <a href="/login">Login</a>
    <a href="/protected">Protected Route</a>`);
});

app.get('/signup', (req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.send(signupHTML);
});

app.post('/signup', async (req, res, next) => {
  const { username, password } = req.body;
  const encryptedPassword = await bcryptjs.hash(password, 10);

  const result = await pool.query(
    'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING *',
    [username, encryptedPassword]
  );

  const user = result.rows[0];
  const payload = {
    id: user.id,
    username: user.username,
  };

  const token = jwt.sign(payload, 'cat', { expiresIn: 36000 });

  //   res.setHeader('authorization', 'Bearer ' + encryptedPassword);
  res.cookie('jwt', token, {
    expires: new Date(Date.now() + 60 * 60 * 1000),
    httpOnly: true,
  });
  res.redirect('/');
});

app.get('/login', (req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.send(`<h1>Login</h1>
    <form method="POST" action="/login">
      <input type="text" name="username" placeholder="Username" required />
      <input type="password" name="password" placeholder="Password" required />
      <button type="submit">Login</button>
    </form>`);
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const result = await pool.query('SELECT * FROM users WHERE username = $1', [
    username,
  ]);

  if (result.rows.length === 0) {
    return res.status(401).send('Invalid username or password');
  }

  const user = result.rows[0];
  const isMatch = await bcryptjs.compare(password, user.password);

  if (!isMatch) {
    return res.status(401).send('Invalid username or password');
  }

  const payload = {
    id: user.id,
    username: user.username,
  };

  const token = jwt.sign(payload, 'cat', { expiresIn: 36000 });

  res.cookie('jwt', token, {
    expires: new Date(Date.now() + 60 * 60 * 1000),
    httpOnly: true,
  });
  res.redirect('/protected');
});

app.get('/posts', isUser, async (req, res, next) => {
  let user;
  if (req.user) user = req.user.username;
  const results = await pool.query(`SELECT * FROM posts`);
  const posts = results.rows;

  const postsHTML = posts
    .map(
      (
        post
      ) => ` <div style="display: grid; grid-template-columns: 3fr 1fr 1fr">
        <span>${post.content}</span>
        <span>${post.createdby}</span>
        <span>${post.createdon}</span>
      </div>`
    )
    .join('');

  res.send(postsHTML);
});

app.post('/posts', isUser, async (req, res, next) => {
  console.log(req.body);
  const { username, post, date } = req.body;

  const options = {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  };

  const dateNew = new Date(Number(date)).toLocaleString('en-US', options);

  await pool.query(
    `INSERT INTO posts (createdBy, content, createdOn) VALUES ($1,$2,$3)`,
    [username, post, dateNew]
  );
  res.redirect('/posts');
});

app.get('/postform', protectedRoute, async (req, res, next) => {
  res.send(` <form method='post' action='/posts'>
        <input type="text" id="username" name="username"  value="${
          req.user.username
        }" />
        <input type="text" id="date" name="date" value="${Date.now()}"  />
        <label for="post">Type your post</label>
        <textarea
            required
          placeholder="Type you post here..."
          id="post"
          name="post"
          rows="4"
          cols="50"
        ></textarea>
        <button>submit post</button>
      </form>`);
});

app.get(
  '/protected',
  protectedRoute,
  restrictedRoute('admin', 'main', 'tu'),
  (req, res) => {
    res.send(`<h1>Congratulations you have accessed the protected route</h1>`);
  }
);

async function protectedRoute(req, res, next) {
  const token = req.cookies.jwt;

  if (!token) {
    return res.redirect('/login');
  }

  const user = await promisify(jwt.verify)(token, 'cat');
  //   console.log(user);

  const result = await pool.query(`SELECT * FROM users WHERE id= $1`, [
    user.id,
  ]);
  const userInDb = result.rows[0];

  if (!userInDb?.id) {
    return res.redirect('/login');
  }

  req.user = userInDb;

  next();
}

function restrictedRoute(...roles) {
  return async (req, res, next) => {
    const role = req.user.role;
    const isAuthorize = roles.includes(role);

    if (!isAuthorize) {
      next(
        new Error(`${req.user.username} is not authorized to visit this route`)
      );
    }
    next();
  };
}

async function isUser(req, res, next) {
  const token = req.cookies?.jwt;

  if (!token) return next();

  const user = jwt.verify(token, 'cat');

  const result = await pool.query(`SELECT * FROM users WHERE id= $1`, [
    user.id,
  ]);

  userInDb = result.rows[0];

  if (!user.id || !userInDb.id) return next();

  req.user = userInDb;
  next();
}

app.use((req, res) => {
  res.send(`<h1>Root not implemented yet</h1>`);
});

app.use((err, req, res, next) => {
  console.log(err);

  res.json({
    status: 'nextError',
    error: err.message,
  });
});

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});

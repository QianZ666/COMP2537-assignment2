require("./utils.js");

require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;
const path = require('path');
const { ObjectId } = require('mongodb');

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const expireTime =1 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include("databaseConnection");

const userCollection = database.db(mongodb_database).collection("users");
app.locals.userCollection = userCollection;

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret:node_session_secret,
    store: mongoStore, //default is memory store
    saveUninitialized: false,
    resave: true,
    cookie: {
      maxAge: expireTime
    }
  })
);
app.set('view engine','ejs');
app.set('views', path.join(__dirname,'views'));

// home page route
app.get("/", (req, res) => {
    res.render("index",{ username: req.session.username});
    });

//middleware for Auth & Admin
function isAuthenticated(req, res, next){
  if (req.session.authenticated)
    return next();
    res.redirect('/login');
}

function isAdmin(req, res, next){
  if (req.session.authenticated && req.session.username){
    req.app.locals.userCollection.findOne({
      username:req.session.username }).then(user => {
        if (user?.user_type ==="admin")
          return next();
        res.status(403).send("403 Error-You are not authorized to view this page.");
      }).catch(err=> {
        res.status(500).send("Internal Server Error");
      });
  } else {
    res.redirect('/login');
  }
}

//nosql-injection
app.get("/nosql-injection", async (req, res) => {
  var username = req.query.user;

  if (!username) {
    res.send(
      `<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`
    );
    return;
  }
  console.log("user: " + username);

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(username);

  //If we didn't use Joi to validate and check for a valid URL parameter below
  // we could run our userCollection.find and it would be possible to attack.
  // A URL parameter of user[$ne]=name would get executed as a MongoDB command
  // and may result in revealing information about all users or a successful
  // login without knowing the correct password.
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.send(
      "<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>"
    );
    return;
  }

  const result = await userCollection
    .find({ username: username })
    .project({ username: 1, password: 1, _id: 1 })
    .toArray();

  console.log(result);

  res.send(`<h1>Hello ${username}</h1>`);
});

// Signup routes
app.get("/signup", (req, res) => {

  const { missingUserName, missingEmail, missingPassword } = req.query;

  res.render("signup", {
    missingUserName: !!missingUserName,
    missingEmail: !!missingEmail,
    missingPassword:!!missingPassword,
  });
});

//login route
app.get("/login", (req, res) => {
  const { error, username} = req.query;
  res.render("login", { error, username});
});

// members route
app.get("/members", (req, res) => {
    if (!req.session.username){
        return res.redirect('/');
    }
    const images = ['cat-1.gif','cat2.gif','cat3.gif'];
    // const randomImage = images[Math.floor(Math.random() * images.length)];

    res.render('members', {
      username: req.session.username,
      images: images
    });  
});

//logout route
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
   res.render("logout");
  });
});

app.get("/loginSubmit", (req, res) => {
  const {error, username } = req.query;
  res.render("loginSubmit",{
  error,
  username: username || ''
  });
});

//admin route
app.get('/admin',isAuthenticated, isAdmin, async (req, res) =>{
  const users = await req.app.locals.userCollection.find().toArray();
  res.render('admin',{username:req.session.username,users});
});
// Submit User route 
app.post("/submitUser", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  const email = req.body.email;

  const schema = Joi.object({
    username: Joi.string().alphanum().max(20).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const { error } = schema.validate(
    { username, email, password },
    { abortEarly: false }
  );

  if (error) {
    const query = [];
    for (const detail of error.details) {
      if (detail.context.key === "username") query.push("missingUserName=true");
      if (detail.context.key === "email") query.push("missingEmail=true");
      if (detail.context.key === "password") query.push("missingPassword=true");
    }
    res.redirect("/signup?" + query.join("&"));
    return;
  }

  try {
    const existingUser = await userCollection.findOne({ 
      $or: [{ username }, { email }]
    });
    
    if (existingUser) {
      let query = [];
      if (existingUser.username === username) query.push("usernameExists=true");
      if (existingUser.email === email) query.push("emailExists=true");
      return res.redirect("/signup?" + query.join("&"));
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ 
      username, 
      email, 
      password: hashedPassword,
      user_type:"user",
      createdAt: new Date()
    });
    req.session.authenticated = true;
    req.session.username = username;
    req.session.email = email;
    return res.redirect("/members");
    
  } catch (err) {
    console.error("Registration error:", err);
    return res.redirect("/signup?error=registration_failed");
  }
});

app.post("/loggingin", async (req, res) => {
  const { username, password } = req.body;

  // Joi validation schema
  const schema = Joi.object({
    username: Joi.string().alphanum().max(20).required(),
    password: Joi.string().min(3).max(20).required()
  });

  // Validate inputs
  const validationResult = schema.validate({ username, password });
  if (validationResult.error) {
    return res.redirect('/loginSubmit?error=validation_error&username=' + encodeURIComponent(username));
  }

  // Find user
  const user = await userCollection.findOne({ username });
  if (!user) {
    return res.redirect('/loginSubmit?error=invalid_credentials&username=' + encodeURIComponent(username));
  }

  // Verify password
  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) {
    return res.redirect('/loginSubmit?error=invalid_credentials&username=' + encodeURIComponent(username));
  }

  // Create session
  req.session.authenticated = true;
  req.session.username = username;
  req.session.email = user.email;
  res.redirect("/members");
});

app.post('/admin/update/:id', isAuthenticated, isAdmin, async (req,res) => {
  const action =req.body.action;
  const newType = action === "promote" ? "admin":"user";
  await req.app.locals.userCollection.updateOne(
    { _id: new ObjectId(req.params.id)},
    { $set: {user_type:newType}}
  );
  res.redirect('/admin');
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
  res.status(404).render("404");
});

app.listen(port, () => {
  console.log("Node application listening on port " + port);
});


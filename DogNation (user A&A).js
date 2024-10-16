//app.js
// Import packages
const express = require("express");
const app = express();
const session = require("express-session");
const passport = require("passport");

// App config
app.set("trust proxy", 1);
const PORT = process.env.PORT || 4001;
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname + '/public'));
app.set("view engine", "ejs");
// Import Passport config
require("./config/passport");

// Session Config
app.use(
  session({
    secret: "randomString",
    cookie: { maxAge: 1000 * 60 * 60 * 24, secure: true, sameSite: 'none'},
    saveUninitialized: false,
    resave: false,
  })
)
// Passport Config
app.use(passport.initialize());
app.use(passport.session());

// Routes
app.use(require("./routes/index.routes"));

app.get("/", (req, res) => {
  const user = req.user || "Guest";
  res.render("home", { user });
});


app.listen(PORT, () => {
  console.log(`Server is listening on port: ${PORT}`);
});


//users.routes.js

const express = require("express");
const router = express.Router();
const helper = require("../helpers/helper");
const passport = require("passport");
const filename = "./data/users.json";
const bcrypt = require("bcrypt");
let users = require("../data/users.json");

// Register New User:
router.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const id = { id: helper.getNewId(users) };
  try {
    const user = await helper.userExists(username);
    if (user) {
      console.log("User already exists!");
      return res.redirect("login");
    }
    // Hash password before storing in local DB:
    const salt = await bcrypt.genSalt(10);
    const hashedPw = await bcrypt.hash(password, salt);
    const newUser = { ...id, username, password: hashedPw };

    // Store new user in local DB
    await users.push(newUser);
    await helper.writeJSONFile(filename, users);

    res.redirect("login");
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Log In User:
router.post(
  "/login",
  passport.authenticate("local", { failureRedirect: "/login" }),
  (req, res) => {
    res.redirect("../");
  }
);

// Log out user:
router.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) return next(err);
    res.redirect("../");
  }); //the req.logout() function is asynchronous in newer versions of Passport. It would be better to handle it with a callback or a promise to ensure the session is properly terminated before redirecting. like done above
});

router.get("/register", (req, res) => {
  res.render("register");
});

router.get("/login", (req, res) => {
  res.render("login");
});

module.exports = router;


// passport.js
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");
const helper = require("../helpers/helper");

// Set up the Passport strategy:
passport.use(
  new LocalStrategy(function (username, password, done) {
    helper.findByUsername(username, async function (err, user) {
      if (err) {
        return done(err);
      }
      if (!user) {
        return done(null, false);
      }
      const matchedPassword = await bcrypt.compare(password, user.password);
      if (!matchedPassword) {
        return done(null, false);
      }
      return done(null, user);
    });
  })
);

// Serialize a user
passport.serializeUser((user , done) => {
  done(null, user.id);
});

// Deserialize a user
passport.deserializeUser((id, done) => {
  helper.findById(id, function (err, user) {
    if (err) {
      return done(err);
    }
    done(null, user);
  });
});



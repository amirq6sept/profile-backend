const bcrypt = require("bcryptjs");
const express = require("express");
const cors = require("cors");
const { Sequelize, DataTypes } = require("sequelize");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors()); 
app.use(express.json()); 

// 1. Database Connection
const sequelize = new Sequelize({
  dialect: "sqlite",
  storage: "./database.sqlite",
  logging: false
});

// 2. THE MISSING PIECE: Defining the User Table!
const User = sequelize.define("User", {
  fullName: { type: DataTypes.STRING, allowNull: false },
  emailAddress: { type: DataTypes.STRING, allowNull: false, unique: true },
  phoneNumber: { type: DataTypes.STRING },
  userPassword: { type: DataTypes.STRING, allowNull: false }
});

// 3. Turn on the Database
sequelize.sync()
  .then(() => console.log("SUCCESS: SQL Database connected!"))
  .catch((err) => console.log("ERROR: Could not connect to SQL.", err));

// --- ROUTES ---

app.get("/", function(request, response) {
  response.json({ message: "Hello from the SQL Backend!" });
});

// --- SECURE Register Route ---
app.post("/api/register", async function(request, response) {
  try {
    const incomingData = request.body;
    
    // 1. Generate the cryptographic salt and hash the password!
    // The '10' is the salt rounds (how many times it scrambles it)
    const hashedPassword = await bcrypt.hash(incomingData.userPassword, 10);

    const newUser = await User.create({
      fullName: incomingData.fullName,
      emailAddress: incomingData.emailAddress,
      phoneNumber: incomingData.phoneNumber,
      // 2. Save the HASHED password to the database, NOT the plain text one!
      userPassword: hashedPassword 
    });

    console.log("SQL saved a new user with a hashed password!");
    response.json({ status: "Success", message: "User saved securely!" });

  } catch (error) {
    console.log("SQL Error:", error.message);
    response.status(400).json({ status: "Error", message: "Email might already exist." });
  }
});

// --- SECURE Login Route ---
app.post("/api/login", async function(request, response) {
  try {
    const loginAttempt = request.body;
    
    const foundUser = await User.findOne({
      where: { emailAddress: loginAttempt.email }
    });

    if (!foundUser) {
      return response.status(401).json({ status: "Error", message: "Invalid email or password." });
    }

    // 1. Use Bcrypt to compare the typed password against the hashed database password
    const isPasswordValid = await bcrypt.compare(loginAttempt.password, foundUser.userPassword);

    // 2. If it matches, let them in!
    if (isPasswordValid) {
      const userToken = jwt.sign(
        { email: foundUser.emailAddress }, 
        "MY_SUPER_SECRET_KEY_123", 
        { expiresIn: "1h" }
      );

      response.json({
        status: "Success",
        message: "Welcome back securely!",
        name: foundUser.fullName,
        token: userToken 
      });
    } else {
      // Password was wrong!
      response.status(401).json({ status: "Error", message: "Invalid email or password." });
    }

  } catch (error) {
    console.log("SQL Error:", error.message);
    response.status(500).json({ status: "Error", message: "Server error." });
  }
});


// --- NEW: Protected Profile Route ---
app.get("/api/profile", async function(request, response) {
  try {
    // 1. Grab the token from the request headers envelope
    const authHeader = request.headers["authorization"];
    
    if (!authHeader) {
      return response.status(401).json({ status: "Error", message: "No token provided. Access Denied." });
    }

    // The header looks like: "Bearer abc123xyz..."
    // We split it by the space and take the second part (the actual token)
    const token = authHeader.split(" ")[1];

    // 2. Verify the token signature using our secret password
    jwt.verify(token, "MY_SUPER_SECRET_KEY_123", async function(error, decodedPayload) {
      if (error) {
        return response.status(403).json({ status: "Error", message: "Invalid or expired token." });
      }

      // 3. If verified, the token opens up and gives us the email we hid inside it!
      const userEmail = decodedPayload.email;

      // 4. Look up this specific user in our SQL database
      const user = await User.findOne({ where: { emailAddress: userEmail } });

      if (!user) {
        return response.status(404).json({ status: "Error", message: "User not found." });
      }

      // 5. Send their profile details back to React!
      response.json({
        status: "Success",
        profile: {
          fullName: user.fullName,
          emailAddress: user.emailAddress,
          phoneNumber: user.phoneNumber
        }
      });
    });

  } catch (error) {
    console.log("SQL Error:", error.message);
    response.status(500).json({ status: "Error", message: "Server error." });
  }
});


// --- NEW: Protected Profile Update Route (CRUD: Update) ---
app.put("/api/profile", async function(request, response) {
  try {
    // 1. Grab and verify the token (Our Security Guard)
    const authHeader = request.headers["authorization"];
    if (!authHeader) {
      return response.status(401).json({ status: "Error", message: "Access Denied." });
    }
    const token = authHeader.split(" ")[1];

    jwt.verify(token, "MY_SUPER_SECRET_KEY_123", async function(error, decodedPayload) {
      if (error) {
        return response.status(403).json({ status: "Error", message: "Invalid token." });
      }

      const userEmail = decodedPayload.email;
      const incomingUpdates = request.body;

      // 2. Find the user in the SQL Database
      const user = await User.findOne({ where: { emailAddress: userEmail } });
      if (!user) {
        return response.status(404).json({ status: "Error", message: "User not found." });
      }

      // 3. Update the SQL rows with the new data from React
      user.fullName = incomingUpdates.fullName;
      user.phoneNumber = incomingUpdates.phoneNumber;

      // 4. Tell the database to lock the changes in the hard drive
      await user.save();

      response.json({
        status: "Success",
        message: "Profile updated permanently in SQL database!"
      });
    });

  } catch (error) {
    console.log("SQL Error:", error.message);
    response.status(500).json({ status: "Error", message: "Server error." });
  }
});


// --- DEPLOYMENT UPDATE: Dynamic Ports ---
// This tells the server: "Use the cloud provider's port, OR use 3000 if I am testing on my laptop"
const PORT = process.env.PORT || 3000;

app.listen(PORT, function() {
  console.log(`Server is running on port ${PORT}`);
});
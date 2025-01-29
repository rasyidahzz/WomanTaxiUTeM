const express = require('express');
const app = express();
const port = process.env.PORT || 3000;
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const saltRounds = 10;

const uri = "mongodb+srv://b122310195:ObVqzWduuotQaUNh@cluster0.1rpwq.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

app.use(express.json());

app.get('/', async (req, res) => {
    res.send('Hello! Welcome To Women Taxi UTeM!');
});

// Registration route
app.post('/register', async (req, res) => {
  const user = await client.db("WomenTaxiUTeM").collection("users").findOne(
      { username: { $eq: req.body.username } }
  );
  if (user) {
      res.send('Username already exists');
      return;
  }
  const icNumber = req.body.ic_number;
  const genderFromIC = parseInt(icNumber.charAt(icNumber.length - 1)) % 2 === 0 ? 'female' : 'male';
  if (genderFromIC !== 'female' || req.body.gender.toLowerCase() !== 'female') {
      res.send('Registration failed: Only female drivers are allowed to register.');
      return;
  }
  const hash = bcrypt.hashSync(req.body.password, saltRounds);
  await client.db("WomenTaxiUTeM").collection("users").insertOne({
      "name": req.body.name,
      "username": req.body.username,
      "password": hash,
      "role": req.body.role, // Add role 
      "gender": req.body.gender,
      "ic_number": req.body.ic_number
  });
  res.send('Register Success: ' + req.body.username);
});

// Login routes
app.get('/login/admin', async (req, res) => {
    try {
        const user = await client.db("WomenTaxiUTeM").collection("users").findOne(
            { username: req.body.username, role: 'admin' }
        );

        if (!user) {
            res.send('Username does not exist');
            return;
        }

        const match = bcrypt.compareSync(req.body.password, user.password);

        if (match) {
            const token = jwt.sign({
                userId: user._id,
                role: user.role
            }, 'wtpassword', { expiresIn: '1h' });

            res.json({ token: token });
        } else {
            res.send('Login failed');
        }
    } catch (error) {
        res.status(500).send('Error logging in');
    }
});

app.get('/login/driver', async (req, res) => {
    try {
        const user = await client.db("WomenTaxiUTeM").collection("users").findOne(
            { username: { $eq: req.body.username }, role: { $eq: 'driver' } }
        );

        if (!user) {
            res.send('Username does not exist');
            return;
        }

        const match = bcrypt.compareSync(req.body.password, user.password);

        if (match) {
            var token = jwt.sign({
                userId: user._id,
                role: user.role
            }, 'wtpassword', { expiresIn: '1h' });

            res.send({ token : token, driverId: user._id});
        } else {
            res.send('Login failed');
        }
    } catch (error) {
        res.status(500).send('Error logging in');
    }
});

app.get('/login/passenger', async (req, res) => {
    try {
        const user = await client.db("WomenTaxiUTeM").collection("users").findOne(
            { username: req.body.username, role: 'passenger' }
        );

        if (!user) {
            res.send('Username does not exist');
            return;
        }

        const match = bcrypt.compareSync(req.body.password, user.password);

        if (match) {
            const token = jwt.sign({
                userId: user._id,
                role: user.role
            }, 'wtpassword', { expiresIn: '1h' });

            res.json({ token: token });
        } else {
            res.send('Login failed');
        }
    } catch (error) {
        res.status(500).send('Error logging in');
    }
});

// Update routes
app.put('/admin/users', verifyToken, async (req, res) => {
  const userId = req.body.id; // Get the user ID from the request body
  const updatedUser = {
      name: req.body.name,
      username: req.body.username,
      role: req.body.role
  };
  try {
      await client.db("WomenTaxiUTeM").collection("users").updateOne({ _id: new ObjectId(userId) }, { $set: updatedUser });
      res.send('User updated');
  } catch (error) {
      res.status(500).send('Error updating user');
  }
});

app.put('/driver/profile', verifyToken, checkRole('driver'), async (req, res) => {
    const driverId = req.user.userId;
    const updatedUser = {
        username: req.body.username,
        password: bcrypt.hashSync(req.body.password, saltRounds)
    };

    const user = await client.db("WomenTaxiUTeM").collection("users").findOne({ _id: new ObjectId(driverId) });

    if (!user) {
        return res.status(404).send('User not found');
    }

    await client.db("WomenTaxiUTeM").collection("users").updateOne({ _id: new ObjectId(driverId) }, { $set: updatedUser });
    res.send('Profile updated');
});

app.put('/passenger/profile', verifyToken, checkRole('passenger'), async (req, res) => {
  const passengerId = req.user.userId;
  const updatedUser = {
      username: req.body.username,
      password: bcrypt.hashSync(req.body.password, saltRounds)
  };

  const user = await client.db("WomenTaxiUTeM").collection("users").findOne({ _id: new ObjectId(passengerId) });

  if (!user) {
      return res.status(404).send('User not found');
  }

  await client.db("WomenTaxiUTeM").collection("users").updateOne({ _id: new ObjectId(passengerId) }, { $set: updatedUser });
  res.send('Profile updated');
});

// Delete routes
app.delete('/admin/users/:id', verifyToken, checkRole('admin'), async (req, res) => {
    const userId = req.params.id;

    try {
        const result = await client.db("WomenTaxiUTeM").collection("users").deleteOne({ _id: new ObjectId(userId) });

        if (result.deletedCount === 1) {
            res.send('User deleted successfully');
        } else {
            res.status(404).send('User not found');
        }
    } catch (error) {
        res.status(500).send('Error deleting user');
    }
});

app.delete('/driver/account', verifyToken, checkRole('driver'), async (req, res) => {
    try {
        const { username, password } = req.body;

        // Step 1: Retrieve the user document by username
        const user = await client.db("WomenTaxiUTeM").collection("users").findOne({ username });

        if (!user) {
            console.log('Account not found for username: ' + username);
            return res.status(404).json({ message: 'Account not found.' });
        }

        // Step 2: Verify the provided password matches the stored password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            console.log('Invalid password for username: ' + username);
            return res.status(401).json({ message: 'Invalid password.' });
        }

        // Step 3: Proceed to delete the user account
        const result = await client.db("WomenTaxiUTeM").collection("users").deleteOne({ username });

        if (result.deletedCount === 1) {
            console.log('Account : ' + username + ' deleted');
            res.status(200).json({ message: 'Account deleted successfully.' });
        } else {
            console.log('Failed to delete account for username: ' + username);
            res.status(500).json({ message: 'Failed to delete account.' });
        }
    } catch (error) {
        console.error('Error deleting account:', error);
        res.status(500).json({ message: 'Internal server error.' });
    }
});

app.delete('/passenger/account', verifyToken, checkRole('passenger'), async (req, res) => {
  try {
    const { username, password } = req.body;

    // Step 1: Retrieve the user document by username
    const user = await client
      .db("WomenTaxiUTeM").collection("users").findOne({ username });

    if (!user) {
      console.log('Account not found for username: ' + username);
      return res.status(404).json({ message: 'Account not found.' });
    }

    // Step 2: Verify the provided password matches the stored password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      console.log('Invalid password for username: ' + username);
      return res.status(401).json({ message: 'Invalid password.' });
    }

    // Step 3: Proceed to delete the user account
    const result = await client.db("WomenTaxiUTeM").collection("users").deleteOne({ username });

    if (result.deletedCount === 1) {
      console.log('Account : ' + username + ' deleted');
      res.status(200).json({ message: 'Account deleted successfully.' });
    } else {
      console.log('Failed to delete account for username: ' + username);
      res.status(500).json({ message: 'Failed to delete account.' });
    }
  } catch (error) {
    console.error('Error deleting account:', error);
    res.status(500).json({ message: 'Internal server error.' });
  }
});


// Additional routes and functions
app.get('/admin/users', verifyToken, checkRole('admin'), async (req, res) => {
    try {
        const users = await client.db("WomenTaxiUTeM").collection("users").find({ role: { $in: ['driver', 'passenger'] } }).toArray();
        res.json(users);
    } catch (error) {
        res.status(500).send('Error fetching users');
    }
});

app.get('/admin/rides', async (req, res) => {
    try {
        const rides = await client.db("WomenTaxiUTeM").collection("rides").find().toArray();
        res.json(rides);
    } catch (error) {
        res.status(500).send('Error fetching rides');
    }
});

app.post('/driver/register/car', verifyToken, checkRole('driver'), async (req, res) => {
  try {
    const driverId = req.user.userId; // Get the driver's userId from the token
    // Check if the driver exists
    const existingDriver = await client.db("WomenTaxiUTeM").collection("users").findOne({ _id: new ObjectId(driverId), role: 'driver' });
    if (!existingDriver) {
      return res.status(404).send('Driver not found');
    }
    // Register the car
    const newCar = {
      driverId: new ObjectId(driverId),
      licensePlate: req.body.licensePlate,
      color: req.body.color,
      model: req.body.model,
    };
    await client.db("WomenTaxiUTeM").collection("car").insertOne(newCar);
    res.status(201).send('Car registered successfully');
  } catch (error) {
    console.error(error);
    res.status(500).send('Error registering car');
  }
});

app.get('/driver/passengers', verifyToken, checkRole('driver'), async (req, res) => {
  try {
    const passengers = await client.db("WomenTaxiUTeM").collection("users").find({ role: 'passenger' },{ WomenTaxiUTeMion: { name: 1 } }).toArray();
    res.json(passengers);
  } catch (error) {
    res.status(500).send('Error fetching passengers');
  }
});

app.post('/driver/accept-ride', verifyToken, checkRole('driver'), async (req, res) => {
  try {
    const { rideId } = req.body; // Get rideId from the request body
    const driverId = req.user.userId; // Driver's userId from the token

    // Validate if rideId is provided
    if (!rideId) {
      return res.status(400).send('Ride ID is required');
    }

    // Check if the ride exists and is in "requested" status with no driver assigned
    const ride = await client.db("WomenTaxiUTeM").collection("rides").findOne({ _id: new ObjectId(rideId), status: 'requested', driverId: null });

    if (ride) {
      // Update the ride to "accepted" and assign the driver's ID
      await client.db("WomenTaxiUTeM").collection("rides").updateOne({ _id: new ObjectId(rideId) }, {$set: { status: 'accepted',driverId: new ObjectId(driverId) }});

      res.send('Ride accepted');
    } else {
      res.send('Ride not available for acceptance or already taken');
    }
  } catch (error) {
    console.error(error);
    res.status(500).send('Server error');
  }
});

app.post('/passenger/request-ride', verifyToken, checkRole('passenger'), async (req, res) => {
  const ride = {
    passengerId: req.user.userId,
    driverId: null,
    pickupLocation: req.body.pickupLocation,
    dropoffLocation: req.body.dropoffLocation,
    status: 'requested',
  };
  try {
    const result = await client.db("WomenTaxiUTeM").collection("rides").insertOne(ride);
    const rideId = result.insertedId; // This is the generated rideId
    res.json({ message: 'Ride requested', rideId: rideId });
  } catch (error) {
    res.status(500).send('Error requesting ride');
  }
});

app.post('/passenger/ride-details', verifyToken, checkRole('passenger'), async (req, res) => {
  try {
    const { rideId } = req.body;

    // Fetch the ride details for the given rideId and passengerId
    const ride = await client.db("WomenTaxiUTeM").collection("rides").findOne({ _id: new ObjectId(rideId) });

    if (!ride) {
      return res.status(404).json({ error: 'Ride not found or not assigned to this passenger' });
    }

    // Fetch the driver's car details using the driverId from the ride
    if (ride.driverId) {
      const car = await client.db("WomenTaxiUTeM").collection("car").findOne({ driverId: new ObjectId(ride.driverId) });
          // Check if car details were found
    if (!car) {
      return res.status(404).json({ error: 'Car details not found for the assigned driver' });
    }
    else res.status(200).json({
      rideId: ride._id,
      status: ride.status,
      driverId: ride.driverId,
      car: {
        licensePlate: car.licensePlate,
        color: car.color,
        model: car.model
      }
    });
  }
    // Respond with ride details including the car information
  } catch (error) {
    console.error('Error fetching ride details:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

async function run() {
  try {
    await client.connect();
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    //await client.close();
  }
}
run().catch(console.dir);

function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, "wtpassword", (err, decoded) => {
    if (err) return res.sendStatus(403);

    req.user = decoded;

    next();
  });
}

function checkRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.sendStatus(403);
    }
    next();
  };
}

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
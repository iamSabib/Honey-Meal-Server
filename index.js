require('dotenv').config();
const express = require('express');
const cors = require('cors');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
// const jwt = require('jsonwebtoken');
// const cookieParser = require('cookie-parser');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const app = express();
const port = process.env.PORT || 5000;


//middleware
// const corsOptions = {
//     origin: [
//         'http://localhost:5173', // for local development
//         'https://honey-meal.web.app', // your production frontend URL
//         'https://honey-meal.firebaseapp.com', // any alternate frontend URL
//     ],
//     credentials: true, // allow cookies to be sent
//     allowedHeaders: ['Content-Type', 'Authorization'], // allowed headers
//     methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'], // allowed HTTP methods
// };
// app.use(cors(corsOptions));
app.use(cors());
app.use(express.json());    // Parse incoming JSON payloads

// app.use(cookieParser());
// app.use((req, res, next) => {
//     const allowedOrigins = [
//         'http://localhost:5173',
//         'https://honey-meal.web.app',
//         'https://honey-meal.firebaseapp.com',
//     ];
//     const origin = req.headers.origin;
//     if (allowedOrigins.includes(origin)) {
//         res.header('Access-Control-Allow-Origin', origin);
//     }
//     res.header('Access-Control-Allow-Credentials', 'true');
//     res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH');
//     res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
//     next();
// });



//will use later
// const verifyToken = (req, res, next) => {
//     const token = req.cookies?.token;
//     console.log('Cookies:', token);
//     if (!token) {
//         console.log("No Token Found");
//         return res.status(401).send({ message: 'Access Denied' });
//     }
//     jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
//         if (err) return res.status(403).send({ message: 'Invalid Token' });
//         req.user = decoded;
//         console.log("Decoded JWT:", decoded);
//         next();
//     });
// };




//mongodb connection


const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.9gttp.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: false,
        deprecationErrors: true,
        
    }
});

async function run() {
    try {
        const db = client.db('HoneyMeal');
        const userCollection = db.collection('users');
        const adminCollection = db.collection('admins');
        const mealCollection = db.collection('meals');
        const upcomingMealCollection = db.collection('upcoming-meals');
        const reviewCollection = db.collection('reviews');
        const mealRequestCollection = db.collection('mealrequest');
        const paymentCollection = db.collection('payments');

        Promise.all([
            mealCollection.createIndex({ title: "text", category: "text"}),
            mealCollection.createIndex({ likes: -1, reviewsCount: -1 }),
            mealCollection.createIndex({ category: 1 }),
            mealCollection.createIndex({ price: 1 }),
            mealCollection.createIndex({ likedby: 1 }),
            mealCollection.createIndex({ "distributor.email": 1 }),
            mealCollection.createIndex({ postTime: -1 })
        ])
        .then(() => console.log("All indexes created successfully"))
        .catch(err => console.error("Error creating indexes:", err));
        

        //indexing
        // await mealCollection.createIndex({ title: 1 });
        // await mealCollection.createIndex({ category: 1 });
        // await mealCollection.createIndex({ "distributor.email": 1 });
        // await mealCollection.createIndex({ rating: -1 });
        // await mealCollection.createIndex({ likes: -1 });
        // await mealCollection.createIndex({ reviewsCount: -1 });
        // await mealCollection.createIndex({ postTime: -1 });



        // {
        //     "_id": "ObjectId",
        //     "name": "John Doe",
        //     "email": "john.doe@example.com",
        //     "password": "hashed_password",
        //     "role": "student",  // Possible values: "admin", "student"
        //     "profilePicture": "profile_url",
        //     "badge": "Bronze",  // Default: "Bronze", options: ["Bronze", "Silver", "Gold", "Platinum"]
        //     "paymentHistory": [
        //       {
        //         "package": "Silver",
        //         "amount": 20,
        //         "paymentDate": "2025-01-01T12:00:00Z"
        //       }
        //     ],
        //     "requestedMeals": [
        //       {
        //         "mealId": "ObjectId",
        //         "status": "Pending"  // Options: "Pending", "Delivered"
        //       }
        //     ],

        // Get all users from userCollection
        app.get('/users', async (req, res) => {
            try {
                const { username, email, page = 1, limit = 10 } = req.query; // Get query parameters from the request
                // console.log(page, limit);

                // Build the filter object based on the provided parameters
                let filter = {};
                if (email) {
                    filter.email = { $regex: new RegExp(email, 'i') }; // Case-insensitive search for email
                }
                if (username) {
                    filter.name = { $regex: new RegExp(username, 'i') }; // Case-insensitive search for username
                }

                // Get total users count based on the filter to calculate total pages
                const totalUsers = await userCollection.countDocuments(filter);

                // Fetch users based on the filter, applying pagination
                const users = await userCollection
                    .find(filter)
                    .skip((page - 1) * limit) // Skip the number of users to get based on page
                    .limit(parseInt(limit)) // Limit the number of users per page
                    .toArray();

                // Calculate total pages
                const totalPages = Math.ceil(totalUsers / limit);

                // Send success response with users data and pagination info
                res.status(200).send({
                    message: 'Users retrieved successfully',
                    users,
                    totalPages,
                });
            } catch (error) {
                // Handle any errors during the database query
                console.error('Error retrieving users:', error);
                res.status(500).send({
                    message: 'Failed to retrieve users',
                    error: error.message,
                });
            }
        });


        // Get user by email
        app.get('/users/:email', async (req, res) => {
            try {
                const { email } = req.params; // Get the email from the URL parameter

                // Fetch the user by email
                const user = await userCollection.findOne({ email });

                if (!user) {
                    return res.status(404).send({
                        message: 'User not found',
                    });
                }

                // Send success response with the user data
                res.status(200).send({
                    message: 'User retrieved successfully',
                    user,
                });
            } catch (error) {
                // Handle any errors during the database query
                console.error('Error retrieving user:', error);
                res.status(500).send({
                    message: 'Failed to retrieve user',
                    error: error.message,
                });
            }
        });



        // Make user an admin
        app.post('/make-admin', async (req, res) => {
            const { userId } = req.body;

            try {
                // Find the user in userCollection
                const user = await userCollection.findOne({ _id: new ObjectId(userId) });

                if (!user) {
                    return res.status(404).send({ message: 'User not found' });
                }

                // Update user's role to 'admin'
                await userCollection.updateOne(
                    { _id: new ObjectId(userId) },
                    { $set: { role: 'admin' } }
                );

                // Create new admin entry
                const newAdmin = {
                    name: user.name,
                    email: user.email,
                    noOfMealsAdded: 0,
                    mealsAdded: []
                };

                // Insert into adminCollection
                await adminCollection.insertOne(newAdmin);

                res.status(200).send({ message: 'User has been promoted to admin successfully' });
            } catch (error) {
                console.error('Error promoting user to admin:', error);
                res.status(500).send({ message: 'Failed to promote user to admin', error: error.message });
            }
        });


        //see if user is admin
        app.get('/is-admin', async (req, res) => {
            //check in db if user is admin
            const email = req?.query?.email;
            if (!email) return res.status(400).send({ message: "credentials missing" })
            const user = await userCollection.findOne({ email: email });
            if (user && user.role === 'admin') {
                res.send({ isAdmin: true });
            } else {
                res.send({ isAdmin: false });
            }
        });

        //get admin for `http://localhost:5000/admin/${user.email}` client used tan stack query.
        app.get('/admin/:email', async (req, res) => {
            // console.log('Admin requested for:', req.params.email);
            const email = req.params.email;
            const admin = await adminCollection.findOne({ email: email });
            res.send(admin);
        });



        // {
        //     "_id": "ObjectId",
        //     "name": "Admin Name",
        //     "email": "admin@example.com",
        //     "password": "hashed_password",
        //     "noOfMealsAdded": 0,
        //     "mealsAdded": [
        //       {
        //         "mealId": "ObjectId",
        //         "title": "Grilled Chicken Salad"
        //       }
        //     ]
        //   }

        //create admin at db
        app.post('/create-admin', async (req, res) => {
            const { name, email } = req.body;
            const newAdmin = {
                name,
                email,
                noOfMealsAdded: 0,
                mealsAdded: [],
            };

            const result = await adminCollection.insertOne(newAdmin);
            res.status(201).send({ message: 'Admin created successfully', adminId: result.insertedId });

        });

        //create user
        app.post('/create-user', async (req, res) => {
            const { name, email } = req.body;

            // Validate input data
            if (!name || !email) {
                return res.status(400).send({ message: 'All fields are required' });
            }

            try {
                const userCollection = client.db('HoneyMeal').collection('users');
                const newUser = {
                    name,
                    email,
                    role: 'student',
                    badge: 'Bronze', // Default badge
                    paymentHistory: [],
                    requestedMeals: []
                };

                const existingUser = await userCollection.findOne({ email });
                if (existingUser) {
                    return res.status(400).send({ message: 'User already exists' });
                }

                const result = await userCollection.insertOne(newUser);
                res.status(201).send({ message: 'User created successfully', userId: result.insertedId });
                // console.log('User created successfully',result);
            } catch (error) {
                console.error('Error creating user:', error);
                res.status(500).send({ message: 'Internal Server Error' });
            }
        });


        //add meal
        // {
        //     "_id": "ObjectId",
        //     "title": "Grilled Chicken Salad",
        //     "category": "Lunch",  // Possible values: "Breakfast", "Lunch", "Dinner"
        //     "image": "meal_image_url",
        //     "ingredients": ["Chicken", "Lettuce", "Tomatoes"],
        //     "description": "Healthy and delicious grilled chicken salad.",
        //     "price": 12.99,
        //     "postTime": "2025-01-01T10:00:00Z",
        //     "distributor": {
        //       "name": "Admin Name",
        //       "email": "admin@example.com"
        //     },
        //     "rating": 4.5,
        //     "likes": 15,
        //     "reviewsCount": 3,
        //     "reviews": [
        //       {
        //         "reviewId": "ObjectId",
        //         "userId": "ObjectId",
        //         "comment": "Amazing taste!",
        //         "rating": 5
        //       }
        //     ]
        //   }

        //get all meals
        // app.get('/meals', async (req, res) => {
        //     const meals = await mealCollection.find({}).toArray();
        //     res.send(meals);
        // });

        // Get all meals with optional search, category filter, and price range filter
        // Get meals with filter by category and price range

        // app.get('/meals', async (req, res) => {
        //     const { category, priceRange, sortBy } = req.query;
        //     // Construct filter object
        //     let filter = {};
        //     let sort = {};

        //     // Filter by category
        //     if (category && category !== 'All') {
        //         filter.category = category;
        //     }

        //     // Filter by price range
        //     if (priceRange) {
        //         const { min, max } = JSON.parse(priceRange); // Assuming priceRange is passed as a stringified object
        //         if (min && max) {
        //             filter.price = { $gte: min, $lte: max };
        //         }
        //     }

        //     // Sort by likes or review count if provided
        //     if (sortBy) {
        //         console.log(sortBy)
        //         if (sortBy === 'likes') {
        //             sort.likes = -1; // -1 for descending order
        //         } else if (sortBy === 'reviewsCount') {
        //             sort.reviewsCount = -1; // -1 for descending order
        //         }
        //     }

        //     try {
        //         const meals = await mealCollection.find(filter).sort(sort).toArray();
        //         res.send(meals);
        //     } catch (error) {
        //         console.error('Error fetching meals:', error);
        //         res.status(500).send({ message: 'Error fetching meals' });
        //     }
        // });

        //2nd
        // app.get('/meals', async (req, res) => {
        //     const { category, priceRange, sortBy, page = 1, limit = 100 } = req.query; // Default to page 1 and limit 10
        //     let filter = {};
        //     let sort = {};

        //     if (category && category !== 'All') {
        //         filter.category = category;
        //     }

        //     if (priceRange) {
        //         const { min, max } = JSON.parse(priceRange);
        //         if (min && max) {
        //             filter.price = { $gte: min, $lte: max };
        //         }
        //     }

        //     if (sortBy) {
        //         if (sortBy === 'likes') {
        //             sort.likes = -1;
        //         } else if (sortBy === 'reviewsCount') {
        //             sort.reviewsCount = -1;
        //         }
        //     }

        //     try {
        //         const meals = await mealCollection
        //             .find(filter)
        //             .sort(sort)
        //             .skip((page - 1) * limit) // Skip previous pages
        //             .limit(parseInt(limit)) // Limit results
        //             .toArray();

        //         const totalMeals = await mealCollection.countDocuments(filter); // Total documents for pagination

        //         res.send({
        //             meals,
        //             totalMeals,
        //             totalPages: Math.ceil(totalMeals / limit),
        //             currentPage: parseInt(page),
        //         });
        //     } catch (error) {
        //         console.error('Error fetching meals:', error);
        //         res.status(500).send({ message: 'Error fetching meals' });
        //     }
        // });

        app.get('/meals', async (req, res) => {
            const { category, priceRange, sortBy, page = 1, limit = 9999 } = req.query; // Default to page 1 and limit 10
            let filter = {};
            let sort = {};

            if (category && category !== 'All') {
                filter.category = category;
            }

            if (priceRange) {
                const { min, max } = JSON.parse(priceRange);
                // console.log("min",min,"max",max)

                filter.price = { $gte: min, $lte: max };

            }

            if (sortBy) {
                if (sortBy === 'likes') {
                    sort.likes = -1;
                } else if (sortBy === 'reviewsCount') {
                    sort.reviewsCount = -1;
                }
            }

            try {
                const meals = await mealCollection
                    .find(filter)
                    .sort(sort)
                    .skip((page - 1) * limit) // Skip previous pages
                    .limit(parseInt(limit)) // Limit results
                    .toArray();

                const totalMeals = await mealCollection.countDocuments(filter); // Total documents for pagination
                // console.log("here",meals)
                res.send({
                    meals,
                    totalMeals,
                    totalPages: Math.ceil(totalMeals / limit),
                    currentPage: parseInt(page),
                });
            } catch (error) {
                console.error('Error fetching meals:', error);
                res.status(500).send({ message: 'Error fetching meals' });
            }
        });



        // GET upcoming meals, sorted by likes count (in descending order)
        app.get('/upcoming-meals', async (req, res) => {
            const { category, priceRange } = req.query;

            try {
                // Fetch meals from upcomingMealCollection and sort by likes count in descending order
                const upcomingMeals = await upcomingMealCollection.find({}).sort({ likes: -1 }).toArray();
                res.send(upcomingMeals);
            } catch (error) {
                console.error('Error fetching upcoming meals:', error);
                res.status(500).send({ message: 'Error fetching upcoming meals' });
            }
        });

        // Like upcoming meal
        app.post('/like-upcoming-meal', async (req, res) => {
            const { mealId, userEmail } = req.body;

            try {
                // Fetch user data from the database based on the provided email
                const user = await userCollection.findOne({ email: userEmail });

                if (!user) {
                    return res.status(404).send({ message: 'User not found' });
                }

                // Check the user's badge and ensure they are allowed to like
                if (user.badge === 'Bronze') {
                    return res.status(403).send({ message: 'You need a subscription to like meals. Please upgrade your badge.' });
                }

                // Update the meal in the database by pushing the userEmail into the 'likedby' array
                // and incrementing the 'likes' count by 1
                const updatedMeal = await upcomingMealCollection.updateOne(
                    { _id: new ObjectId(mealId) }, // Find the meal by its ID
                    {
                        $addToSet: { likedby: userEmail }, // Add email to 'likedby' array if not already there
                        $inc: { likes: 1 }  // Increment the 'likes' count by 1
                    }
                );

                if (updatedMeal.matchedCount === 0) {
                    return res.status(404).send({ message: 'Meal not found' });
                }

                // Fetch the updated meal to check its like count
                const meal = await upcomingMealCollection.findOne({ _id: new ObjectId(mealId) });

                if (meal.likes >= 10) {
                    // Move the meal to the 'meal' collection if likes >= 10
                    const { status, ...mealData } = meal;

                    // Add the meal to the meals collection
                    const result = await mealCollection.insertOne(mealData);

                    if (result.insertedId) {
                        // Delete the meal from the upcoming meals collection
                        await upcomingMealCollection.deleteOne({ _id: new ObjectId(mealId) });

                        return res.status(201).send({ message: 'Meal added successfully from upcoming meal', mealId: result.insertedId });
                    } else {
                        return res.status(500).send({ message: 'Failed to add meal' });
                    }
                }

                // Send success message after the meal is liked
                res.send({ message: 'Meal liked successfully' });
            } catch (error) {
                console.error('Error liking meal:', error);
                res.status(500).send({ message: 'Error liking the meal' });
            }
        });




        //get all revies from reviewCollection
        // Get all reviews or filter by user email
        app.get('/reviews', async (req, res) => {
            try {
                const { email, page = 1, limit = 10 } = req.query; // Get email from query params

                let query = {}; // Default: get all reviews
                if (email) {
                    query.email = email; // Filter by email if provided
                }

                const reviews = await reviewCollection.find(query).skip((page - 1) * limit).limit(parseInt(limit)).toArray();

                const totalReviews = await reviewCollection.countDocuments();



                if (reviews.length === 0) {
                    return res.status(200).send({ message: 'No reviews found' });
                }

                res.status(200).send({ message: 'Reviews retrieved successfully', reviews, totalReviews, totalPages: Math.ceil(totalReviews / limit), currentPage: parseInt(page), });
            } catch (error) {
                console.error('Error retrieving reviews:', error);
                res.status(500).send({ message: 'Failed to retrieve reviews' });
            }
        });


        //wite get usersemails all revuew

        // Get meal request collection
        app.get('/meal-requests', async (req, res) => {
            try {
                let { username, email, page = 1, limit = 10 } = req.query;
        
                page = parseInt(page);
                limit = parseInt(limit);
        
                const filter = {};
                if (username && username.trim()) {
                    filter.name = { $regex: new RegExp(username, 'i') };
                }
                if (email && email.trim()) {
                    filter.email = { $regex: new RegExp(email, 'i') };
                }
        
                const totalMealRequests = await mealRequestCollection.countDocuments(filter);
                const mealRequests = await mealRequestCollection
                    .find(filter)
                    .skip((page - 1) * limit)
                    .limit(limit)
                    .toArray();
        
                // Instead of 404, return empty data with totalPages = 0
                res.status(200).send({
                    message: 'Meal requests retrieved successfully',
                    mealRequests,
                    totalMealRequests,
                    totalPages: Math.ceil(totalMealRequests / limit) || 1,
                    currentPage: page
                });
        
            } catch (error) {
                console.error('Error retrieving meal requests:', error);
                res.status(500).send({ message: 'Failed to retrieve meal requests' });
            }
        });
        

        app.get('/meal-requests-user', async (req, res) => {
            try {
                const { email, page = 1, limit = 10 } = req.query; // Only use email as filter

                // Fetch meal requests based on the email
                const mealRequests = await mealRequestCollection.find({ email }).skip((page - 1) * limit).limit(parseInt(limit)).toArray();

                if (mealRequests.length === 0) {
                    return res.status(200).send({ message: 'No meal requests found' });
                }

                const totalRequest = await mealRequestCollection.countDocuments(); // Total documents for pagination


                // Loop through meal requests and add likes and reviews count
                const updatedMealRequests = await Promise.all(
                    mealRequests.map(async (mealRequest) => {
                        const mealId = mealRequest.mealId; // Get mealId from mealRequest
                        // Fetch meal details using mealId
                        const meal = await mealCollection.findOne({ _id: new ObjectId(mealId) });
                        if (meal) {
                            // Add likes and reviewsCount to the meal request
                            mealRequest.likes = meal.likes;
                            mealRequest.reviewsCount = meal.reviewsCount;
                        } else {
                            // If meal not found, keep likes and reviewsCount as null or handle accordingly
                            mealRequest.likes = null;
                            mealRequest.reviewsCount = null;
                        }

                        return {
                            mealRequest,

                        };
                    })
                );

                res.status(200).send({
                    message: 'Meal requests retrieved successfully', mealRequests: updatedMealRequests, totalRequest,
                    totalPages: Math.ceil(totalRequest / limit),
                    currentPage: parseInt(page),
                });
            } catch (error) {
                console.error('Error retrieving meal requests:', error);
                res.status(500).send({ message: 'Failed to retrieve meal requests' });
            }
        });

        app.post("/review-delete", async (req, res) => {
            try {
                const { email, reviewId, mealId } = req.body;

                if (!email || !reviewId || !mealId) {
                    return res.status(400).json({ message: "Missing required fields" });
                }

                // Step 1: Delete the review from reviewCollection
                const reviewDeleteResult = await reviewCollection.deleteOne({ _id: new ObjectId(reviewId) });

                if (reviewDeleteResult.deletedCount === 0) {
                    return res.status(404).json({ message: "Review not found or already deleted" });
                }

                // Step 2: Find the meal and remove the review from its reviews array
                const mealUpdateResult = await mealCollection.updateOne(
                    { _id: new ObjectId(mealId) },
                    { $pull: { reviews: { email: email } } } // Remove only the object where email matches
                );

                if (mealUpdateResult.modifiedCount === 0) {
                    return res.status(404).json({ message: "Meal not found or review not present in meal or already deleted" });
                }

                return res.status(200).json({ message: "Review deleted successfully" });

            } catch (error) {
                console.error("Error deleting review:", error);
                res.status(500).json({ message: "Internal server error" });
            }
        });

        //update review
        app.post("/review-update", async (req, res) => {
            try {
                const { email, reviewId, mealId, newComment } = req.body;

                // Step 1: Update the review in the `reviewCollection`
                const reviewUpdateResult = await reviewCollection.updateOne(
                    { _id: new ObjectId(reviewId) }, // Ensure it's the correct review
                    { $set: { comment: newComment } } // Update the comment
                );

                // Step 2: Update the review in the `mealCollection` reviews array
                const mealUpdateResult = await mealCollection.updateOne(
                    { _id: new ObjectId(mealId) },
                    { $set: { "reviews.$[review].comment": newComment } }, // Update the comment of the matched review
                    {
                        arrayFilters: [{ "review.email": email }] // Find the review object with the matching email
                    }
                );

                if (reviewUpdateResult.modifiedCount > 0 && mealUpdateResult.modifiedCount > 0) {
                    return res.status(200).json({ message: "Review updated successfully" });
                } else {
                    return res.status(400).json({ message: "Review update failed" });
                }
            } catch (error) {
                console.error("Error updating review:", error);
                return res.status(500).json({ message: "Internal Server Error" });
            }
        });



        // Handle the DELETE request to cancel the meal
        app.delete('/meal-requests-user', async (req, res) => {
            try {
                const { id } = req.body;  // Get the id from the request body
                // console.log("id", id);

                if (!id) {
                    return res.status(400).send({ message: 'Meal request ID is required' });
                }

                // Delete the meal request by id
                const result = await mealRequestCollection.deleteOne({ _id: new ObjectId(id) });

                if (result.deletedCount === 0) {
                    return res.status(404).send({ message: 'Meal request not found' });
                }

                res.status(200).send({ message: 'Meal request deleted successfully' });
            } catch (error) {
                console.error('Error deleting meal request:', error);
                res.status(500).send({ message: 'Failed to delete meal request' });
            }
        });



        // Change status to 'served' from 'pending' by meal request _id
        app.patch('/meal-requests/:id', async (req, res) => {
            const { id } = req.params; // Extract the meal request ID from the URL
            try {
                // Find the meal request by ID and update its status
                const result = await mealRequestCollection.updateOne(
                    { _id: new ObjectId(id) }, // Search by the provided _id
                    { $set: { status: 'served' } } // Change the status to 'served'
                );

                if (result.matchedCount === 0) {
                    return res.status(404).send({ message: 'Meal request not found' });
                }

                if (result.modifiedCount === 0) {
                    return res.status(400).send({ message: 'Status already set to served' });
                }

                res.status(200).send({ message: 'Meal request status updated to served' });
            } catch (error) {
                console.error('Error updating meal request:', error);
                res.status(500).send({ message: 'Failed to update meal request status' });
            }
        });




        //get meal by id
        app.get('/meals/:id', async (req, res) => {
            const id = req.params.id;
            const meal = await mealCollection.findOne({ _id: new ObjectId(id) });
            res.send(meal);
        });

        //like meal by user email
        app.post('/meals/:id/like', async (req, res) => {
            const id = req.params.id;
            const email = req.body.email;
            const meal = await mealCollection.findOne({ _id: new ObjectId(id) });

            //check if user already liked the meal
            if (meal.likedby.includes(email)) {
                return res.status(400).send({ message: 'User already liked the meal' });
            }

            meal.likedby.push(email);
            meal.likes++;
            await mealCollection.updateOne({ _id: new ObjectId(id) }, { $set: meal });
            res.send(meal);
        });

        // Post a review by user for a meal
        app.post('/meals/:id/review', async (req, res) => {
            const id = req.params.id;
            const { email, comment, rating } = req.body;
            const meal = await mealCollection.findOne({ _id: new ObjectId(id) });

            // Check if user already reviewed the meal
            if (meal.reviews.some(review => review.email === email)) {
                return res.status(400).send({ message: 'User already reviewed the meal' });
            }

            const user = await userCollection.findOne({ email });
            // Create the review object
            const newReview = {
                name: user.name,
                email,
                comment,
                rating,
                createdAt: new Date().toISOString(), // Set current date/time
                likes: 0, // Initialize likes for the review
                title: meal.title,
                mealId: id
            };

            // Add the review to the meal's reviews array
            meal.reviews.push(newReview);
            meal.reviewsCount++;

            // Calculate new average rating
            const totalRating = meal.reviews.reduce((acc, review) => acc + review.rating, 0);
            const newAverageRating = totalRating / meal.reviewsCount;

            // Save the review to the reviews collection with meal id
            // const reviewCollection = client.db('HoneyMeal').collection('reviews');
            // newReview.mealId = id; // Add meal id to the review object
            // newReview.title = meal.title

            await reviewCollection.insertOne(newReview);

            // Update the meal's rating and save the meal document
            meal.rating = newAverageRating;
            await mealCollection.updateOne({ _id: new ObjectId(id) }, { $set: meal });


            // Send the updated meal data as response
            res.send({ message: 'Review posted successfully', meal });
        });


        //post a meal requst, will have user email and mealid, in to  mealrequestCollections
        // POST request to create a meal request
        //title, user email, name, status
        app.post('/meal/request', async (req, res) => {
            // console.log("hit");
            const { email, mealId } = req.body;

            const user = await userCollection.findOne({ email: email });
            // console.log("user", user)
            const name = user.name;
            const badge = user.badge;
            // console.log(badge);

            // Check if the user is Bronze
            if (badge === "Bronze") {
                // console.log("hit")
                return res.send({ message: "Need to buy subscription" }); // Early return to stop further execution
            }

            const meal = await mealCollection.findOne({ _id: new ObjectId(mealId) });
            const title = meal.title;

            try {
                // Create a new meal request entry
                const mealRequest = {
                    email,
                    name,
                    title,
                    mealId: meal._id,
                    status: "pending",
                    createdAt: new Date(),
                };

                // Insert the meal request into the collection
                await mealRequestCollection.insertOne(mealRequest);

                // Respond with success message
                res.status(201).send({ message: 'Meal request sent successfully!' });
            } catch (error) {
                console.error(error);
                res.status(500).send({ message: 'Something went wrong. Please try again.' });
            }
        });




        //post a meal
        app.post('/meals', async (req, res) => {
            const { title, category, image, ingredients, description, price, postTime, distributor, rating, likes, reviewsCount, reviews } = req.body;
            const newMeal = {
                title, category, image, ingredients, description, price, postTime, distributor, rating, likes, reviewsCount, reviews, likedby: [],
            };
            const result = await mealCollection.insertOne(newMeal);
            res.status(201).send({ message: 'Meal added successfully', mealId: result.insertedId });
            //admin collection update
            const admin = await adminCollection.findOne({ email: distributor.email });
            admin.mealsAdded.push({ mealId: result.insertedId, title });
            admin.noOfMealsAdded++;
            await adminCollection.updateOne({ email: distributor.email }, { $set: admin });

        });

        // Reset reviewCount, rating, and reviews for a meal
        app.patch('/meals/reset/:id', async (req, res) => {
            const mealId = req.params.id;

            try {
                const result = await mealCollection.updateOne(
                    { _id: new ObjectId(mealId) }, // Find the meal by its ID
                    {
                        $set: {
                            reviewsCount: 0,
                            rating: 0,
                            reviews: []
                        }
                    }
                );

                if (result.matchedCount === 0) {
                    return res.status(404).send({ message: 'Meal not found' });
                }

                res.status(200).send({ message: 'Meal reset successfully' });
            } catch (error) {
                console.error('Error resetting meal:', error);
                res.status(500).send({ message: 'Failed to reset meal' });
            }
        });


        // Patch a meal
        app.patch('/meals/:id', async (req, res) => {
            const { id } = req.params;  // Get meal ID from URL parameter
            const updateData = req.body;  // Get the fields to be updated from the request body

            // Find the meal by its ID
            const meal = await mealCollection.findOne({ _id: new ObjectId(id) });

            if (!meal) {
                return res.status(404).send({ message: 'Meal not found' });
            }

            // Update only the fields that are present in the request body
            const updatedMeal = {
                ...meal,
                ...updateData,  // Merge existing meal data with the update fields
            };

            // Update the meal in the database
            await mealCollection.updateOne({ _id: new ObjectId(id) }, { $set: updatedMeal });

            res.status(200).send({ message: 'Meal updated successfully', updatedMeal });
        });


        // Delete a meal
        app.delete('/meals/:mealId', async (req, res) => {
            const { mealId } = req.params;

            try {
                // Find the meal to delete
                const meal = await mealCollection.findOne({ _id: new ObjectId(mealId) });
                if (!meal) {
                    return res.status(404).send({ message: 'Meal not found' });
                }

                // Remove meal from admin's meal list and decrement count
                const distributorEmail = meal.distributor.email;
                const admin = await adminCollection.findOne({ email: distributorEmail });

                if (admin) {
                    admin.mealsAdded = admin.mealsAdded.filter((mealItem) => mealItem.mealId.toString() !== mealId);
                    admin.noOfMealsAdded = Math.max(0, admin.noOfMealsAdded - 1); // Ensure no negative count
                    await adminCollection.updateOne(
                        { email: distributorEmail },
                        { $set: { mealsAdded: admin.mealsAdded, noOfMealsAdded: admin.noOfMealsAdded } }
                    );
                }

                // Delete the meal from mealCollection
                const result = await mealCollection.deleteOne({ _id: new ObjectId(mealId) });

                if (result.deletedCount === 1) {
                    res.status(200).send({ message: 'Meal deleted successfully' });
                } else {
                    res.status(500).send({ message: 'Failed to delete the meal' });
                }
            } catch (error) {
                console.error('Error deleting meal:', error);
                res.status(500).send({ message: 'Internal server error' });
            }
        });


        // POST the upcoming meal to the meal collection
        app.post('/meals/from-upcoming', async (req, res) => {
            const { upcomingMealId } = req.body;

            if (!upcomingMealId) {
                return res.status(400).send({ message: 'Upcoming meal ID is required' });
            }

            // Retrieve the upcoming meal from the database
            const upcomingMeal = await upcomingMealCollection.findOne({ _id: new ObjectId(upcomingMealId) });

            if (!upcomingMeal) {
                return res.status(404).send({ message: 'Upcoming meal not found' });
            }

            // Remove the 'status' field from the upcoming meal
            const { status, ...mealData } = upcomingMeal;

            // Add the meal to the meals collection
            const result = await mealCollection.insertOne(mealData);

            if (result.insertedId) {
                // Delete the meal from the upcoming meals collection
                await upcomingMealCollection.deleteOne({ _id: new ObjectId(upcomingMealId) });

                return res.status(201).send({ message: 'Meal added successfully from upcoming meal', mealId: result.insertedId });
            } else {
                return res.status(500).send({ message: 'Failed to add meal' });
            }
        });



        // POST an upcoming meal
        app.post('/upcoming-meals', async (req, res) => {
            const { title, category, image, ingredients, description, price, postTime, distributor, rating, likes, reviewsCount, reviews } = req.body;

            // Create the new upcoming meal object
            const newMeal = {
                title,
                category,
                image,
                ingredients,
                description,
                price,
                postTime,
                distributor,
                rating: rating || 0, // Default rating to 0 if not provided
                likes: likes || 0, // Default likes to 0 if not provided
                reviewsCount: reviewsCount || 0, // Default reviews count to 0 if not provided
                reviews: reviews || [], // Default to empty array if no reviews
                likedby: [], // Empty array for people who liked the meal
                status: 'pending', // Default status for upcoming meal
            };

            try {
                // Insert the new meal into the upcomingMeals collection
                const result = await upcomingMealCollection.insertOne(newMeal);

                // Send the response with the success message and mealId
                res.status(201).send({ message: 'Upcoming meal added successfully', mealId: result.insertedId });

                // Update the admin collection to track meals added by the admin (distributor)
                const admin = await adminCollection.findOne({ email: distributor.email });
                if (admin) {
                    admin.mealsAdded.push({ mealId: result.insertedId, title });
                    admin.noOfMealsAdded++;
                    await adminCollection.updateOne({ email: distributor.email }, { $set: admin });
                } else {
                    console.log(`Admin with email ${distributor.email} not found.`);
                }
            } catch (error) {
                console.error("Error adding upcoming meal:", error);
                res.status(500).send({ message: "Failed to add upcoming meal. Try again." });
            }
        });


        //payment apis
        app.get('/payments/:email', async (req, res) => {
            const query = { email: req.params.email }
            // if (req.params.email !== req.decoded.email) {
            //   return res.status(403).send({ message: 'forbidden access' });
            // }
            const result = await paymentCollection.find(query).toArray();
            res.send(result);
        })

        // payment intent
        app.post('/create-payment-intent', async (req, res) => {
            const { price } = req.body;
            const amount = parseInt(price * 100);
            // console.log(amount, 'amount inside the intent')

            const paymentIntent = await stripe.paymentIntents.create({
                amount: amount,
                currency: 'usd',
                payment_method_types: ['card']
            });

            res.send({
                clientSecret: paymentIntent.client_secret
            })
        });

        app.post('/payments', async (req, res) => {
            const payment = req.body;
            const paymentResult = await paymentCollection.insertOne(payment);

            // payment.userPackage
            // payment.email
            const user = await userCollection.updateOne({ email: payment.email }, { $set: { badge: payment.userPackage } })

            // console.log('payment info', payment);
            res.send(paymentResult);
        })


    } catch(error){ console.error("error",error)}
     finally {

    }
}
run().catch(console.dir);


app.get('/welcome', (req, res) => {
    res.send({ message: "welcome" })
})

app.get('/', (req, res) => {
    res.send('Catering Server is running');
});





app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const moment = require("moment");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const cors = require("cors");
const app = express();
require("dotenv").config();
const port = 5000;

app.use(cors());
app.use(express.json());

const uri = `mongodb+srv://${process.env.DB_User}:${process.env.DB_Pass}@cluster0.ocam1.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const jwt_secret = process.env.JWT_SECRET;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();
    // Send a ping to confirm a successful connection

    const usersCollection = client.db("shopSphere").collection("users");
    const productsCollection = client.db("shopSphere").collection("products");
    const categoriesCollection = client
      .db("shopSphere")
      .collection("categories");
    const vendorsCollection = client.db("shopSphere").collection("Vendors");
    const purchasesCollection = client.db("shopSphere").collection("purchases");
    const paymentsCollection = client.db("shopSphere").collection("payments");

    // verify token
    const verifyToken = (req, res, next) => {
      if (!req.headers.authorization) {
        return res.status(401).send({ message: "Unauthorized access" });
      }
      const token = req.headers.authorization.split(" ")[1];

      jwt.verify(token, jwt_secret, (err, decoded) => {
        if (err) {
          return res.status(403).send({ message: "Forbidden access" });
        }
        req.decoded = decoded;
        next();
      });
    };

    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded.email;
      const query = { email: email };
      const user = await usersCollection.findOne(query);
      isAdmin = user?.role === "admin";
      if (!isAdmin) {
        return res.status(403).send({ message: "Forbidden access" });
      }
      next();
    };

    // Users
    app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
      const result = await usersCollection
        .aggregate([
          {
            $addFields: {
              isAdmin: { $cond: [{ $eq: ["$role", "admin"] }, 1, 0] },
            },
          },
          { $sort: { isAdmin: -1, _id: -1 } },
        ])
        .toArray();
      res.send(result);
    });

    app.get("/user/:email", async (req, res) => {
      const email = req.params.email;
      const filter = { email: email };
      const user = await usersCollection.findOne(filter);
      const isAdmin = user?.role === "admin";
      res.send({ admin: isAdmin });
    });

    app.patch("/user/:id", verifyToken, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const { newRole } = req.body;
      const query = { _id: new ObjectId(id) };
      const update = {
        $set: {
          role: newRole,
        },
      };
      const result = await usersCollection.updateOne(query, update);
      res.send(result);
    });

    // Authentication Part
    app.post("/signup", async (req, res) => {
      const { name, email, password, created_at } = req.body;
      const existingUser = await usersCollection.findOne({ email });
      if (existingUser) {
        return res.status(400).send({ message: "Email already exists!" });
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = {
        name,
        email,
        password: hashedPassword,
        role: "user",
        created_at,
      };
      const result = await usersCollection.insertOne(user);
      const token = jwt.sign(
        { id: result.insertedId, email, role: "user" },
        jwt_secret,
        { expiresIn: "1h" }
      );
      res.send({ message: "user created successfully", token, name, email });
    });

    app.post("/signin", async (req, res) => {
      const userData = req.body;
      const { email, password } = userData;

      const user = await usersCollection.findOne({ email });
      if (!user) {
        return res.status(400).send({ message: "Invalid email or password!" });
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(400).send({ message: "Invalid email or password!" });
      }

      const token = jwt.sign(
        { id: user._id, email: user.email, role: user.role },
        jwt_secret,
        { expiresIn: "1h" }
      );

      const userInfo = await usersCollection.findOne({ email: email });

      res.send({
        message: "Login successful",
        token,
        name: userInfo.name,
        email,
      });
    });

    app.get("/categories", verifyToken, verifyAdmin, async (req, res) => {
      const result = await categoriesCollection
        .find()
        .sort({ _id: -1 })
        .toArray();
      res.send(result);
    });

    // Category Part
    app.post("/categories", verifyToken, verifyAdmin, async (req, res) => {
      const { category_name, created_by, email, created_date, active } =
        req.body;
      const lastElement = await categoriesCollection.findOne(
        {},
        { sort: { category_id: -1 } }
      );
      const newCategory = {
        category_id: lastElement ? lastElement.category_id + 1 : 1,
        category_name,
        created_by,
        email,
        created_date,
        active,
      };
      const result = await categoriesCollection.insertOne(newCategory);
      res.send(result);
    });

    app.patch("/category/:id", verifyToken, verifyAdmin, async (req, res) => {
      const { active } = req.body;
      const { id } = req.params;
      const query = { _id: new ObjectId(id) };
      const update = {
        $set: { active: active },
      };
      const result = await categoriesCollection.updateOne(query, update);
      res.send(result);
    });

    app.patch(
      "/category-name/:id",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const id = req.params.id;
        const { updated_name } = req.body;
        const query = { _id: new ObjectId(id) };
        const updatedName = {
          $set: { category_name: updated_name },
        };
        const result = await categoriesCollection.updateOne(query, updatedName);
        res.send(result);
      }
    );

    // product Part

    app.post("/products", verifyToken, verifyAdmin, async (req, res) => {
      const product = req.body;
      const result = await productsCollection.insertOne(product);
      res.send(result);
    });

    app.get("/products", verifyToken, verifyAdmin, async (req, res) => {
      const { currentCategory, searchText } = req.query;
      let query = {};
      const activeCategories = await categoriesCollection
        .find({ active: true })
        .toArray();
      const activeCategoriesName = activeCategories.map(
        (cat) => cat.category_name
      );

      if (currentCategory && currentCategory !== "all") {
        if (activeCategoriesName.includes(currentCategory)) {
          query.category = currentCategory;
        } else {
          query.category = { $in: activeCategoriesName };
        }
      } else {
        query.category = { $in: activeCategoriesName };
      }

      if (searchText) {
        query.product_name = { $regex: searchText, $options: "i" };
      }
      const result = await productsCollection.find(query).toArray();
      res.send(result);
    });

    app.patch("/products/:id", verifyToken, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const updateProductData = req.body;
      const query = { _id: new ObjectId(id) };
      const updatedData = {
        $set: {
          product_name: updateProductData.product_name,
          product_img: updateProductData.product_img,
          category: updateProductData.category,
          product_price: updateProductData.product_price,
          discount_price: updateProductData.discount_price,
          description: updateProductData.description,
        },
      };
      const result = await productsCollection.updateOne(query, updatedData);
      res.send(result);
    });

    app.delete("/products/:id", verifyToken, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await productsCollection.deleteOne(query);
      res.send(result);
    });

    // vendor section
    app.post("/vendors", async (req, res) => {
      const vendor = req.body;
      const lastElement = await vendorsCollection.findOne(
        {},
        { sort: { vendor_id: -1 } }
      );
      const vendorId = lastElement ? parseInt(lastElement.vendor_id) + 1 : 1;
      const newVendor = {
        vendor_id: vendorId.toString(),
        name: vendor.name,
        email: vendor.email,
        number: vendor.number,
        address: vendor.address,
        created_at: moment().format("MM-DD-YYYY"),
      };
      const result = await vendorsCollection.insertOne(newVendor);
      res.send(result);
    });

    app.get('/payments', async(req,res)=>{
      const vendorId = req.query.v;
      const query = { vendor : vendorId, status: "unpaid"};
      const projection = { vendor: 1, product: 1, total_price: 1 };
      const result = await purchasesCollection.find(query).project(projection).toArray();
      res.send(result);
    })

    app.get('/payments/:v', async(req,res)=> {
      const vendor = req.params.v;
      const query = {  vendor_id : vendor };
      const result = await paymentsCollection.findOne(query);
      res.send(result);
    })

    app.get("/vendors", async (req, res) => {
      const result = await vendorsCollection.find().sort({_id : -1}).toArray();
      res.send(result);
    });

    app.post("/purchases", async (req, res) => {
      const purchase = req.body;

      const purchaseEntry = {
        vendor: purchase.vendor,
        product: purchase.product,
        quantity: parseInt(purchase.quantity),
        unit_price: purchase.unit_price,
        total_price: parseInt(purchase.quantity)*parseInt(purchase.unit_price),
        note: purchase.note,
        status: "unpaid",
        purchase_at: moment().toString(),
      };

      purchaseResult = await purchasesCollection.insertOne(purchaseEntry);

      // 2nd part
      const productId = purchase.product;

      const updateResult = await productsCollection.updateOne(
        { _id: new ObjectId(productId) },
        { $inc: { quantity: parseInt(purchase.quantity) } }
      );

      // 3rd part
      const vendor_id = purchase.vendor;
      const current_balance = await paymentsCollection.findOne(
        { vendor_id },{ projection: { balance: 1,_id: 0 } }) || { balance: 0 };
      const cash_out = {
        product: purchase.product,
        cash_out: parseInt(purchase.unit_price) * parseInt(purchase.quantity),
        balance_after_cash_out: current_balance.balance - (parseInt(purchase.unit_price) * parseInt(purchase.quantity)),
        note: purchase.note,
        at: moment().format(),
      };

      const existPayment = await paymentsCollection.findOne({ vendor_id });
      if (existPayment) {
        const updateQuery = {
          $push: { payments: cash_out },
          $set: { 
            balance: existPayment.balance - (parseInt(purchase.unit_price) * parseInt(purchase.quantity))
          }
        };
        await paymentsCollection.updateOne({ vendor_id }, updateQuery);
      } else {
        const payment = { vendor_id, balance: 0 - (parseInt(purchase.unit_price) * parseInt(purchase.quantity)), payments: [cash_out] };
        await paymentsCollection.insertOne(payment);
      }

      res.send({ purchaseResult, updateResult });
    });



    app.post("/cash-in", async (req, res) => {
     const cashIn = req.body;
     const current_balance = await paymentsCollection.findOne({vendor_id : cashIn.vendor_id},{ projection: { balance: 1,_id: 0 } })
     const parseCashIn = JSON.parse(cashIn.cash_in);
     const newCashIn = {
      product : parseCashIn.product,
      cash_in : parseInt(parseCashIn.total_price),
      balance_after_cash_in: current_balance.balance + parseInt(parseCashIn.total_price) ,
      note: cashIn.note,
      at: moment().format()
     } 
     const query = { vendor_id: cashIn.vendor_id }
     const updateData = {
      $push : {payments: newCashIn},
      $set : {balance: current_balance.balance + parseInt(parseCashIn.total_price)}
     }
     const result = await paymentsCollection.updateOne(query, updateData);

     const productId = parseCashIn.productId;
     const updatePurchaseStatus = await purchasesCollection.updateOne({_id : new ObjectId(productId)}, { $set: { status: 'paid'}})

     res.send({result, updatePurchaseStatus})
    });



    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("ShopSphere is Running");
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});

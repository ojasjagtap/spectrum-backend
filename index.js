require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

// Handle preflight OPTIONS requests explicitly
app.options('*', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*'); // Update with specific origins in production
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.sendStatus(204); // No Content
});

const PORT = process.env.PORT || 5000;

mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error(err));

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  userType: String,
  linkedChildren: {
    type: [mongoose.Schema.Types.ObjectId],
    ref: "User",
    default: [],
  },
  linkedSupports: {
    type: [mongoose.Schema.Types.ObjectId],
    ref: "User",
    default: [],
  },
  stars: { type: Number, default: 0 },
});

const taskSchema = new mongoose.Schema({
  name: { type: String, required: true },
  steps: { type: [String], required: true },
  image: { type: String, default: "assets/default.png" },
  starsWorth: { type: Number, required: true },
  assignedTo: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  assignedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  status: { type: String, enum: ["pending", "completed"], default: "pending" },
});

const starSchema = new mongoose.Schema({
  name: { type: String, required: true },
  image: { type: String, default: "assets/default.png" },
  value: { type: Number, required: true },
  assignedTo: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  assignedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  status: { type: String, enum: ["pending", "completed"], default: "pending" },
});

const messageSchema = new mongoose.Schema({
  sender: { type: String, required: true },
  receiver: { type: String, required: true },
  message: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
});

const moodSchema = new mongoose.Schema({
  email: { type: String, required: true },
  mood: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
});

const Mood = mongoose.model("Mood", moodSchema);
const Message = mongoose.model("Message", messageSchema);
const User = mongoose.model("User", userSchema);
const Task = mongoose.model("Task", taskSchema);
const Star = mongoose.model("Star", starSchema);

// Routes
app.get("/", (req, res) => {
  res.status(200).send("Server is running!");
});

app.post("/signup", async (req, res) => {
  const { name, email, password, userType } = req.body;

  if (!name || !email || !password || !userType) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      userType,
    });

    await newUser.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    if (error.code === 11000) {
      res.status(400).json({ message: "Email already exists" });
    } else {
      res.status(500).json({ message: "Server error" });
    }
  }
});

app.get('/test', (req, res) => {
  res.status(200).send('Test route is working!');
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    res.status(200).json({ userType: user.userType });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.post("/add-child", async (req, res) => {
  const { supportEmail, childEmail } = req.body;

  if (!supportEmail || !childEmail) {
    return res
      .status(400)
      .json({ message: "Support and child email are required" });
  }

  try {
    const [child, support] = await Promise.all([
      User.findOne({ email: childEmail, userType: "Child" }),
      User.findOne({ email: supportEmail, userType: "Support" }),
    ]);

    if (!child) {
      return res.status(404).json({ message: "Child user not found" });
    }
    if (!support) {
      return res.status(404).json({ message: "Support user not found" });
    }

    const childUpdate = !support.linkedChildren.includes(child._id)
      ? { $addToSet: { linkedChildren: child._id } }
      : null;
    const supportUpdate = !child.linkedSupports.includes(support._id)
      ? { $addToSet: { linkedSupports: support._id } }
      : null;

    const updates = [];
    if (childUpdate) {
      updates.push(User.updateOne({ _id: support._id }, childUpdate));
    }
    if (supportUpdate) {
      updates.push(User.updateOne({ _id: child._id }, supportUpdate));
    }

    if (updates.length > 0) {
      await Promise.all(updates);
    }

    res.status(200).json({ message: "Child linked successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.post("/get-linked-children", async (req, res) => {
  const { supportEmail } = req.body;

  if (!supportEmail) {
    return res.status(400).json({ message: "Support email is required" });
  }

  try {
    const support = await User.findOne({ email: supportEmail })
      .populate({
        path: "linkedChildren",
        select: "name email",
      })
      .select("linkedChildren");

    if (!support) {
      return res.status(404).json({ message: "Support not found" });
    }

    const children = support.linkedChildren.map((child) => ({
      name: child.name,
      email: child.email,
    }));

    res.status(200).json({ children });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.post("/remove-child-link", async (req, res) => {
  const { supportEmail, childEmail } = req.body;

  if (!supportEmail || !childEmail) {
    return res.status(400).json({ message: "Both emails are required" });
  }

  try {
    const [support, child] = await Promise.all([
      User.findOne({ email: supportEmail }),
      User.findOne({ email: childEmail }),
    ]);

    if (!support || !child) {
      return res.status(404).json({ message: "Support or child not found" });
    }

    const updates = await Promise.all([
      User.updateOne(
        { _id: support._id },
        { $pull: { linkedChildren: child._id } }
      ),
      User.updateOne(
        { _id: child._id },
        { $pull: { linkedSupports: support._id } }
      ),
    ]);

    if (updates.some((update) => update.modifiedCount === 0)) {
      return res.status(500).json({ message: "Failed to remove link" });
    }

    res.status(200).json({ message: "Link removed successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.post("/add-task", async (req, res) => {
  const { name, steps, starsWorth, assignedTo, assignedBy } = req.body;

  if (!name || !steps || !starsWorth || !assignedTo || !assignedBy) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const [assignedToUser, assignedByUser] = await Promise.all([
      User.findOne({ email: assignedTo }),
      User.findOne({ email: assignedBy }),
    ]);

    if (!assignedToUser || !assignedByUser) {
      return res.status(404).json({ message: "Child or support not found" });
    }

    const taskExists = await Task.exists({
      name,
      assignedTo: assignedToUser._id,
      assignedBy: assignedByUser._id,
    });

    if (taskExists) {
      return res
        .status(400)
        .json({ message: "Task with the same name already exists" });
    }

    await Task.create({
      name,
      steps,
      starsWorth,
      assignedTo: assignedToUser._id,
      assignedBy: assignedByUser._id,
      status: "pending",
    });

    res.status(200).json({ message: "Task added successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.delete("/delete-task", async (req, res) => {
  const { taskId } = req.body;

  if (!taskId) {
    return res.status(400).json({ message: "Task ID is required" });
  }

  try {
    const deletedTask = await Task.findByIdAndDelete(taskId);

    if (!deletedTask) {
      return res.status(404).json({ message: "Task not found" });
    }

    res.status(200).json({ message: "Task deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.put("/update-task-status", async (req, res) => {
  const { taskId, status } = req.body;

  if (!taskId || !status) {
    return res.status(400).json({ message: "Task ID and status are required" });
  }

  if (!["pending", "completed"].includes(status)) {
    return res.status(400).json({ message: "Invalid status value" });
  }

  try {
    const task = await Task.findByIdAndUpdate(
      taskId,
      { status },
      { new: true }
    );

    if (!task) {
      return res.status(404).json({ message: "Task not found" });
    }

    if (status === "completed") {
      await User.findByIdAndUpdate(task.assignedTo, {
        $inc: { stars: task.starsWorth },
      });
    }

    res.status(200).json({ message: "Task status updated successfully" });
  } catch (error) {
    console.error("Error updating task status:", error.message);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.post("/get-tasks", async (req, res) => {
  const { supportEmail, childEmail } = req.body;

  if (!supportEmail || !childEmail) {
    return res
      .status(400)
      .json({ message: "Support and child emails are required" });
  }

  try {
    const [assignedToUser, assignedByUser] = await Promise.all([
      User.findOne({ email: childEmail }),
      User.findOne({ email: supportEmail }),
    ]);

    if (!assignedToUser || !assignedByUser) {
      return res.status(404).json({ message: "Child or support not found" });
    }

    const [activeTasks, archivedTasks] = await Promise.all([
      Task.find({
        assignedTo: assignedToUser._id,
        assignedBy: assignedByUser._id,
        status: "pending",
      }),
      Task.find({
        assignedTo: assignedToUser._id,
        assignedBy: assignedByUser._id,
        status: "completed",
      }),
    ]);

    res.status(200).json({ activeTasks, archivedTasks });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.put("/update-task", async (req, res) => {
  const { taskId, name, steps, starsWorth } = req.body;

  if (!taskId || !name || !steps || starsWorth == null) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const updatedTask = await Task.findByIdAndUpdate(
      taskId,
      { name, steps, starsWorth },
      { new: true }
    );

    if (!updatedTask) {
      return res.status(404).json({ message: "Task not found" });
    }

    res
      .status(200)
      .json({ message: "Task updated successfully", task: updatedTask });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.post("/get-task-details", async (req, res) => {
  const { taskId } = req.body;

  if (!taskId) {
    return res.status(400).json({ message: "Task ID is required" });
  }

  try {
    const task = await Task.findById(taskId).populate(
      "assignedTo assignedBy",
      "name email"
    );

    if (!task) {
      return res.status(404).json({ message: "Task not found" });
    }

    res.status(200).json(task);
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.post("/add-star", async (req, res) => {
  const { name, value, assignedTo, assignedBy, status } = req.body;

  if (!name || value == null || !assignedTo || !assignedBy) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const [child, support] = await Promise.all([
      User.findOne({ email: assignedTo }),
      User.findOne({ email: assignedBy }),
    ]);

    if (!child || !support) {
      return res.status(404).json({ message: "Child or support not found" });
    }

    const starExists = await Star.exists({
      name,
      assignedTo: child._id,
      assignedBy: support._id,
    });

    if (starExists) {
      return res
        .status(400)
        .json({ message: "Star with the same name already exists" });
    }

    const newStar = await Star.create({
      name,
      value,
      assignedTo: child._id,
      assignedBy: support._id,
      status: status || "pending",
    });

    res.status(200).json({ message: "Star added successfully", star: newStar });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.post("/get-star-details", async (req, res) => {
  const { starId } = req.body;

  if (!starId) {
    return res.status(400).json({ message: "Star ID is required" });
  }

  try {
    const star = await Star.findById(starId).populate(
      "assignedTo assignedBy",
      "name email"
    );

    if (!star) {
      return res.status(404).json({ message: "Star not found" });
    }

    res.status(200).json(star);
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.put("/update-star", async (req, res) => {
  const { starId, name, value, status } = req.body;

  if (!starId || !name || value == null || !status) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const updatedStar = await Star.findByIdAndUpdate(
      starId,
      { name, value, status },
      { new: true }
    );

    if (!updatedStar) {
      return res.status(404).json({ message: "Star not found" });
    }

    res
      .status(200)
      .json({ message: "Star updated successfully", star: updatedStar });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.post("/get-stars", async (req, res) => {
  const { supportEmail, childEmail } = req.body;

  if (!supportEmail || !childEmail) {
    return res
      .status(400)
      .json({ message: "Support and child emails are required" });
  }

  try {
    const [assignedToUser, assignedByUser] = await Promise.all([
      User.findOne({ email: childEmail }),
      User.findOne({ email: supportEmail }),
    ]);

    if (!assignedToUser || !assignedByUser) {
      return res.status(404).json({ message: "Child or support not found" });
    }

    const [activeStars, archivedStars] = await Promise.all([
      Star.find({
        assignedTo: assignedToUser._id,
        assignedBy: assignedByUser._id,
        status: "pending",
      }),
      Star.find({
        assignedTo: assignedToUser._id,
        assignedBy: assignedByUser._id,
        status: "completed",
      }),
    ]);

    res.status(200).json({ activeStars, archivedStars });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.put("/update-star-status", async (req, res) => {
  const { starId, status } = req.body;

  if (!starId || !status) {
    return res.status(400).json({ message: "Star ID and status are required" });
  }

  if (!["pending", "completed"].includes(status)) {
    return res.status(400).json({ message: "Invalid status value" });
  }

  try {
    const updatedStar = await Star.findByIdAndUpdate(
      starId,
      { status },
      { new: true }
    );

    if (!updatedStar) {
      return res.status(404).json({ message: "Star not found" });
    }

    res.status(200).json({ message: "Star status updated", star: updatedStar });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.delete("/delete-star", async (req, res) => {
  const { starId } = req.body;

  if (!starId) {
    return res.status(400).json({ message: "Star ID is required" });
  }

  try {
    const deletedStar = await Star.findByIdAndDelete(starId);

    if (!deletedStar) {
      return res.status(404).json({ message: "Star not found" });
    }

    res
      .status(200)
      .json({ message: "Star deleted successfully", star: deletedStar });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.post("/get-linked-users", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: "Email is required" });
  }

  try {
    const user = await User.findOne({ email })
      .populate("linkedChildren", "name email")
      .populate("linkedSupports", "name email");

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const children = user.linkedChildren || [];
    const supports = user.linkedSupports || [];

    res.status(200).json({ children, supports });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.post("/link-support", async (req, res) => {
  const { currentSupportEmail, newSupportEmail } = req.body;

  if (!currentSupportEmail || !newSupportEmail) {
    return res.status(400).json({ message: "Both emails are required." });
  }

  try {
    const [currentSupport, newSupport] = await Promise.all([
      User.findOne({ email: currentSupportEmail }),
      User.findOne({ email: newSupportEmail }),
    ]);

    if (!currentSupport || !newSupport) {
      return res.status(404).json({ message: "Support user not found." });
    }

    if (newSupport.userType !== "Support") {
      return res
        .status(400)
        .json({ message: "The email does not belong to a support user." });
    }

    await Promise.all([
      User.updateOne(
        { _id: currentSupport._id },
        { $addToSet: { linkedSupports: newSupport._id } }
      ),
      User.updateOne(
        { _id: newSupport._id },
        { $addToSet: { linkedSupports: currentSupport._id } }
      ),
    ]);

    res.status(200).json({ message: "Support linked successfully." });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.post("/get-messages", async (req, res) => {
  const { currentUserEmail, otherUserEmail } = req.body;

  if (!currentUserEmail || !otherUserEmail) {
    return res.status(400).json({ message: "Both emails are required." });
  }

  try {
    const messages = await Message.find({
      $or: [
        { sender: currentUserEmail, receiver: otherUserEmail },
        { sender: otherUserEmail, receiver: currentUserEmail },
      ],
    })
      .select("sender receiver message timestamp")
      .sort({ timestamp: 1 });

    res.status(200).json({ messages });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.post("/send-message", async (req, res) => {
  const { sender, receiver, message } = req.body;

  if (!sender || !receiver || !message) {
    return res.status(400).json({ message: "All fields are required." });
  }

  try {
    const newMessage = await Message.create({ sender, receiver, message });

    res.status(200).json({
      message: "Message sent successfully.",
      messageId: newMessage._id,
    });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.post("/add-mood", async (req, res) => {
  const { email, mood } = req.body;

  if (!email || !mood) {
    return res.status(400).json({ message: "Email and mood are required." });
  }

  try {
    const newMood = await Mood.create({ email, mood });

    res.status(200).json({
      message: "Mood recorded successfully.",
      moodId: newMood._id,
    });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.post("/get-child-tasks", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: "Email is required." });
  }

  try {
    const currentUser = await User.findOne({ email });

    if (!currentUser) {
      return res.status(404).json({ message: "User not found." });
    }

    const tasks = await Task.aggregate([
      { $match: { assignedTo: currentUser._id, status: "pending" } },
      {
        $lookup: {
          from: "users",
          localField: "assignedBy",
          foreignField: "_id",
          as: "supportInfo",
        },
      },
      { $unwind: "$supportInfo" },
      {
        $group: {
          _id: "$supportInfo.name",
          tasks: {
            $push: {
              _id: "$_id",
              name: "$name",
              starsWorth: "$starsWorth",
              image: "$image",
            },
          },
        },
      },
    ]);

    res.status(200).json({
      message: "Tasks fetched successfully.",
      tasks,
    });
  } catch (error) {
    console.error("Error fetching tasks:", error.message);
    res
      .status(500)
      .json({ message: "Error fetching tasks.", error: error.message });
  }
});

app.get("/get-user-stars", async (req, res) => {
  const { email } = req.query;

  if (!email) {
    return res.status(400).json({ message: "Email is required." });
  }

  try {
    const user = await User.findOne({ email }).select("stars");

    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    res.status(200).json({ stars: user.stars });
  } catch (error) {
    console.error("Error fetching user stars:", error.message);
    res.status(500).json({ message: "Server error.", error: error.message });
  }
});

app.post("/get-child-stars", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: "Email is required." });
  }

  try {
    const currentUser = await User.findOne({ email }).select("_id");

    if (!currentUser) {
      return res.status(404).json({ message: "User not found." });
    }

    const stars = await Star.aggregate([
      { $match: { assignedTo: currentUser._id, status: "pending" } },
      {
        $lookup: {
          from: "users",
          localField: "assignedBy",
          foreignField: "_id",
          as: "supportInfo",
        },
      },
      { $unwind: "$supportInfo" },
      {
        $group: {
          _id: "$supportInfo.name",
          stars: {
            $push: {
              _id: "$_id",
              assignedBy: "$assignedBy",
              name: "$name",
              value: "$value",
              image: "$image",
            },
          },
        },
      },
    ]);

    res.status(200).json({
      message: "Stars fetched successfully.",
      stars,
    });
  } catch (error) {
    console.error("Error fetching stars:", error.message);
    res
      .status(500)
      .json({ message: "Error fetching stars.", error: error.message });
  }
});

app.put("/redeem-star", async (req, res) => {
  const { starId, supportId, supportPassword } = req.body;

  if (!starId || !supportId || !supportPassword) {
    return res
      .status(400)
      .json({ message: "Star ID, support ID, and password are required." });
  }

  try {
    const support = await User.findById(supportId);
    if (!support || support.userType !== "Support") {
      return res.status(404).json({ message: "Support user not found." });
    }

    const isPasswordValid = await bcrypt.compare(
      supportPassword,
      support.password
    );
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid password." });
    }

    const star = await Star.findById(starId);
    if (!star || star.status === "completed") {
      return res
        .status(404)
        .json({ message: "Star not found or already redeemed." });
    }

    const child = await User.findById(star.assignedTo).select("stars");
    if (!child) {
      return res.status(404).json({ message: "Child user not found." });
    }

    const session = await mongoose.startSession();
    session.startTransaction();
    try {
      star.status = "completed";
      await star.save({ session });

      child.stars = Math.max(0, child.stars - star.value);
      await child.save({ session });

      await session.commitTransaction();
    } catch (transactionError) {
      await session.abortTransaction();
      throw transactionError;
    } finally {
      session.endSession();
    }

    res.status(200).json({ message: "Star redeemed successfully." });
  } catch (error) {
    console.error("Error redeeming star:", error.message);
    res.status(500).json({ message: "Server error.", error: error.message });
  }
});

app.post("/get-linked-supports", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: "Email is required." });
  }

  try {
    const child = await User.findOne({ email }).populate(
      "linkedSupports",
      "name email"
    );

    if (!child) {
      return res.status(404).json({ message: "Child user not found." });
    }

    const supports = child.linkedSupports || [];

    res.status(200).json({ supports });
  } catch (error) {
    console.error("Error fetching linked supports:", error.message);
    res.status(500).json({ message: "Server error.", error: error.message });
  }
});

app.get("/get-mood-trend", async (req, res) => {
  try {
    const { email, days = 7 } = req.query;

    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }

    const daysInt = parseInt(days, 10);
    if (isNaN(daysInt) || daysInt <= 0) {
      return res.status(400).json({ error: "Days must be a positive number" });
    }

    const startDate = new Date();
    startDate.setDate(startDate.getDate() - daysInt);

    const moods = await Mood.find(
      {
        email,
        timestamp: { $gte: startDate },
      },
      "mood timestamp"
    ).sort({ timestamp: 1 });

    if (!moods.length) {
      return res.status(200).json({
        message: `No mood data available for the past ${daysInt} days.`,
        data: [],
      });
    }

    res.status(200).json({
      message: "Mood trend fetched successfully",
      data: moods,
    });
  } catch (err) {
    console.error("Error fetching mood trend:", err.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Start Server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

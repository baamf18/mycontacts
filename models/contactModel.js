const mongoose = require ("mongoose");

const contactSchema = new  mongoose.Schema(
  {
    user_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true
    },
    name: {
      type: String,
      required: [true, "Please add the contact name"],
    },
    email: {
      type: String,
      required: [true, "Please add the contact email"],
    },
    phone: {
      type: String,
      required: [true, "Please add the contact phone number"],
    }
  },
  {
    timestamps: true
  }
);

module.exports = mongoose.model("Contact", contactSchema);
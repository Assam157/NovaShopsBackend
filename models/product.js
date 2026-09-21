import mongoose from 'mongoose';

const productSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    category: { type: String, default: 'General', trim: true },
    price: { type: Number, default: 0, min: 0 },
    stock: { type: Number, default: 0, min: 0 },
    image: { type: String, default: '', trim: true },
    description: { type: String, default: '', trim: true }
  },
  { timestamps: true }
);

// Expose `id` and hide `_id`/`__v` in JSON responses
productSchema.set('toJSON', {
  virtuals: true,
  versionKey: false,
  transform: (_doc, ret) => {
    ret.id = ret._id.toString();
    delete ret._id;
    return ret;
  }
});

export default mongoose.model('Product', productSchema);
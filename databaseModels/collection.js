const mongoose = require('mongoose');

const CollectionSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    movies: [
        {
            id: Number,
            cover: String,
            rating: Number,
            title: String,
            release_or_publish_year: String
        }
    ],
    shows: [
        {
            id: Number,
            cover: String,
            rating: Number,
            title: String,
            release_or_publish_year: String
        }
    ],
    documentaries: [
        {
            id: Number,
            cover: String,
            rating: Number,
            title: String,
            release_or_publish_year: String
        }
    ],
    books: [
        {
            id: String,
            cover: Number,
            rating: Number,
            title: String,
            release_or_publish_year: String
        }
    ],
    nytbooks: [
        {
            id: String,
            book_image: String,
            title: String,
            author: String
        }
    ]
});

const Collection = mongoose.model('Collection', CollectionSchema);

module.exports = Collection;
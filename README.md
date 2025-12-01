# Lost & Found College Project - Backend

A complete Flask backend for a Lost & Found College Project with MongoDB integration.

## Features

### User Management
- User registration and authentication
- JWT-based authentication
- Password hashing with bcrypt
- Profile management
- Role-based access control (user/admin)

### Lost & Found Items
- Submit lost items
- Submit found items
- View all approved items
- Search and filter items
- Image upload support
- Item status management (pending/approved/rejected)

### Admin Features
- View all items (including pending)
- Approve/reject items
- User management
- Admin statistics dashboard
- Role management

### File Upload
- Image upload for lost/found items
- File type validation
- Secure file storage
- Automatic file cleanup on deletion

## Installation

1. Install dependencies:
\`\`\`bash
pip install flask flask-cors pymongo bcrypt PyJWT python-dotenv Werkzeug
\`\`\`

2. Set up environment variables in `.env`:
\`\`\`env
MONGODB_URI=mongodb://localhost:27017/
DB_NAME=lost_found_db
SECRET_KEY=your-super-secret-key-change-this-in-production
\`\`\`

3. Run the application:
\`\`\`bash
python app.py
\`\`\`

The server will start on `http://localhost:5000`

## API Endpoints

### Authentication
- `POST /api/register` - Register new user
- `POST /api/login` - Login user
- `POST /api/logout` - Logout user
- `PUT /api/edit-profile` - Update user profile

### Items
- `POST /api/lost` - Submit lost item
- `POST /api/found` - Submit found item
- `GET /api/items` - Get all approved items (with filtering)
- `GET /api/item/<id>` - Get single item details
- `PUT /api/item/<id>` - Update item (owner/admin only)
- `DELETE /api/item/<id>` - Delete item (owner/admin only)
- `GET /api/user/items` - Get current user's items

### File Upload
- `POST /api/upload` - Upload image file
- `GET /uploads/<filename>` - Serve uploaded files

### Admin
- `GET /api/admin/items` - View all items (admin only)
- `PUT /api/admin/approve/<id>` - Approve/reject item (admin only)
- `GET /api/admin/users` - Manage users (admin only)
- `PUT /api/admin/user/<id>` - Update user role (admin only)
- `DELETE /api/admin/user/<id>` - Delete user (admin only)
- `GET /api/admin/stats` - Get admin statistics (admin only)

## Database Schema

### Users Collection
\`\`\`json
{
  "_id": "ObjectId",
  "username": "string",
  "email": "string",
  "password": "hashed_string",
  "role": "user|admin",
  "profile": {
    "full_name": "string",
    "phone": "string",
    "created_at": "datetime",
    "updated_at": "datetime"
  }
}
\`\`\`

### Items Collection
\`\`\`json
{
  "_id": "ObjectId",
  "title": "string",
  "description": "string",
  "location": "string",
  "date": "string",
  "category": "string",
  "image": "string",
  "type": "lost|found",
  "status": "pending|approved|rejected",
  "user_id": "string",
  "admin_notes": "string",
  "reviewed_by": "string",
  "reviewed_at": "datetime",
  "created_at": "datetime",
  "updated_at": "datetime"
}
\`\`\`

## Security Features

- JWT token authentication
- Password hashing with bcrypt
- Role-based access control
- File upload validation
- CORS enabled for frontend integration
- Input validation and sanitization

## Frontend Integration

The backend is designed to work with your existing HTML/CSS/JS frontend. Use the API endpoints with proper authentication headers:

\`\`\`javascript
// Example: Login request
fetch('http://localhost:5000/api/login', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    username: 'your_username',
    password: 'your_password'
  })
})
.then(response => response.json())
.then(data => {
  if (data.token) {
    localStorage.setItem('token', data.token);
  }
});

// Example: Authenticated request
fetch('http://localhost:5000/api/user/items', {
  headers: {
    'Authorization': `Bearer ${localStorage.getItem('token')}`
  }
})
.then(response => response.json())
.then(data => console.log(data));
\`\`\`

## File Upload Example

\`\`\`javascript
// Upload image
const formData = new FormData();
formData.append('image', fileInput.files[0]);
formData.append('title', 'Lost Phone');
formData.append('description', 'iPhone 12 Pro');
formData.append('location', 'Library');
formData.append('category', 'Electronics');

fetch('http://localhost:5000/api/lost', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${localStorage.getItem('token')}`
  },
  body: formData
});

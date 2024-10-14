import { useState } from "react";
import "./App.css";
import axios from "axios";
import  { jwtDecode }  from "jwt-decode"
function App() {
  const [user, setUser] = useState(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(false);
  const [success, setSuccess] = useState(false);

axiosJWT= axios.create()  //create many as you want like authentication(login, signup, delete) etc which require token refresh

  axios.interceptors.request.use(async (config) => {
    if (user?.accessToken) {
      const currentDate = new Date();
      const decodedToken = jwtDecode(user.accessToken);
      console.log("decodedToken", decodedToken);

      // Check if the token is expired
      if (decodedToken.exp * 1000 < currentDate.getTime()) {
        console.log("Token expired, refreshing...");
        const data=await refreshToken(); // Automatically refresh the token if expired
        config.headers['authorization'] = "Bearer " + data.accessToken; // Update the access token in headers after refresh
      }
    }
    return config;
  }, (error)=>{
    return Promise.reject(error);
  });




  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post("http://localhost:5000/api/login", {
        username,
        password,
      });
      setUser(res.data);
    } catch (err) {
      console.log(err);
    }
  };
  const handleDelete = async (id) => {
    setSuccess(false);
    setError(false);
    try {
      await axios.delete("http://localhost:5000/api/users/" + id, {
        headers: {
          authorization: "Bearer " + user.accessToken,
        },
      });
      setSuccess(true);
    } catch (err) {
      setError(err);
    }
  };
  const refreshToken = async () => {
    try {
      const response = await axios.get("http://localhost:5000/api/refresh", {
        token: user.refreshToken,
      });
      setUser((prevUser) => ({
        ...prevUser,
        accessToken: response.data.accessToken,
        refreshToken: response.data.refreshToken,
      }));
    } catch (error) {}
  };
  return (
    <>
      <div className="container">
        {user ? (
          <div className="home">
            <span>
              Welcome to the <b>{user.isAdmin ? "admin" : "user"}</b> dashboard{" "}
              <b>{user.username}</b>.
            </span>
            <span>Delete Users:</span>
            <button className="deleteButton" onClick={() => handleDelete(1)}>
              Delete Ahmad
            </button>
            <button className="deleteButton" onClick={() => handleDelete(2)}>
              Delete Aman
            </button>
            {error && (
              <span className="error">
                You are not allowed to delete this user!
              </span>
            )}
            {success && (
              <span className="success">
                User has been deleted successfully...
              </span>
            )}
          </div>
        ) : (
          <div className="login">
            <form onSubmit={handleSubmit}>
              <span className="formTitle">Lama Login</span>
              <input
                type="text"
                placeholder="username"
                onChange={(e) => setUsername(e.target.value)}
              />
              <input
                type="password"
                placeholder="password"
                onChange={(e) => setPassword(e.target.value)}
              />
              <button type="submit" className="submitButton">
                Login
              </button>
            </form>
          </div>
        )}
      </div>
    </>
  );
}

export default App;

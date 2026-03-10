
import React, { useState } from 'react';
import axios from "axios";
import { USER_API_END_POINT } from "../utils/constant";
import toast from "react-hot-toast";
import { useNavigate } from "react-router-dom";
import { useDispatch } from "react-redux";
import { getUser } from '../redux/userSlice';

const Login = () => {
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const navigate = useNavigate();
  const dispatch = useDispatch();

  const submitHandler = async (e) => {
    e.preventDefault();

    if (!username || !password) {
      toast.error("Both fields are required!");
      return;
    }

    try {
      const url = isLogin ? `${USER_API_END_POINT}/login` : `${USER_API_END_POINT}/register`;
      const res = await axios.post(
        url,
        { username, password },
        { headers: { "Content-Type": "application/json" }, withCredentials: true }
      );

      if (res.data.success) {
        toast.success(res.data.message);

        if (isLogin) {
          dispatch(getUser(res.data.user));
          navigate("/");
        } else {
          setIsLogin(true);
          setPassword("");
        }
      }

    } catch (error) {
      const message = error.response?.data?.message || (isLogin ? "Login failed" : "Signup failed");
      toast.error(message);
      console.log(error);
    }
  };

  const toggleMode = () => {
    setIsLogin(!isLogin);
    setPassword("");
  };

  return (
    <div className='w-screen h-screen flex items-center justify-center bg-gradient-to-br from-blue-100 to-blue-300'>
      <div className='bg-white shadow-lg rounded-2xl flex w-4/5 max-w-4xl overflow-hidden'>
        
        {/* Left Image */}
        <div className='hidden md:flex w-1/2 bg-blue-500 items-center justify-center'>
          <img 
            src="https://images.squarespace-cdn.com/content/v1/6636a8a240efc07873f1dbe4/35e2b4ed-6190-4f5f-87cc-391fcf4983a4/nexplaysecure_transparent.PNG?format=1500w" 
            alt="nxp-secure"
            className='w-3/4'
          />
        </div>

        {/* Form */}
        <div className='w-full md:w-1/2 p-10 flex flex-col justify-center'>
          <h1 className='text-3xl font-bold mb-6 text-gray-800'>
            {isLogin ? "Welcome Back!" : "Create Account"}
          </h1>
          <p className='text-gray-500 mb-6'>
            {isLogin ? "Login to access your dashboard." : "Sign up to start using the platform."}
          </p>

          <form onSubmit={submitHandler} className='flex flex-col space-y-4'>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder='Username'
              className="outline-none border border-gray-300 px-4 py-2 rounded-xl focus:ring-2 focus:ring-blue-400 focus:border-transparent"
            />

            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder='Password'
              className="outline-none border border-gray-300 px-4 py-2 rounded-xl focus:ring-2 focus:ring-blue-400 focus:border-transparent"
            />

            <button className='bg-blue-500 hover:bg-blue-600 text-white font-semibold py-2 rounded-xl transition duration-300'>
              {isLogin ? "Login" : "Sign Up"}
            </button>
          </form>

          <p className='text-gray-600 mt-4'>
            {isLogin ? "Don't have an account?" : "Already have an account?"}
            <span onClick={toggleMode} className='text-blue-500 font-bold cursor-pointer ml-1'>
              {isLogin ? "Sign Up" : "Login"}
            </span>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Login;
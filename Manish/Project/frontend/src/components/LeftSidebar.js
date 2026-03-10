import React from 'react';
//import { CiHome, CiHashtag, CiUser, CiBookmark } from "react-icons/ci";
import { CiHome, CiUser} from "react-icons/ci";
//import { IoIosNotificationsOutline } from "react-icons/io";
import { AiOutlineLogout } from "react-icons/ai";
import { Link, useNavigate } from 'react-router-dom';
import { useSelector, useDispatch } from "react-redux";
import axios from "axios";
import { USER_API_END_POINT } from '../utils/constant';
import toast from "react-hot-toast";
import { getUser } from '../redux/userSlice';

const LeftSidebar = () => {
  const { user } = useSelector(store => store.user);
  const navigate = useNavigate();
  const dispatch = useDispatch();

  const logoutHandler = async () => {
    try {
      const res = await axios.get(`${USER_API_END_POINT}/logout`);
      dispatch(getUser(null));
      navigate('/login');
      toast.success(res.data.message);
    } catch (error) {
      console.log(error);
    }
  }

  return (
    <div className='flex flex-col h-full p-4'>
     
{/* Logo */}
<div className="flex justify-center mb-8">
  <img
    src="https://images.squarespace-cdn.com/content/v1/6636a8a240efc07873f1dbe4/35e2b4ed-6190-4f5f-87cc-391fcf4983a4/nexplaysecure_transparent.PNG?format=1500w"
    alt="Nexplay Secure-Logo"
    className="w-40 h-auto object-contain"
  />
</div>



      {/* Menu */}
      <div className='flex flex-col gap-2'>
        <Link to="/" className='flex items-center px-4 py-2 hover:bg-gray-200 rounded-full'>
          <CiHome size={24} />
          <h1 className='ml-2 font-bold text-lg'>Home</h1>
        </Link>
        
       
        <Link to={`/profile/${user?._id}`} className='flex items-center px-4 py-2 hover:bg-gray-200 rounded-full'>
          <CiUser size={24} />
          <h1 className='ml-2 font-bold text-lg'>Profile</h1>
        </Link>
        
        <div 
          onClick={logoutHandler} 
          className='flex items-center px-4 py-2 hover:bg-gray-200 rounded-full cursor-pointer'
        >
          <AiOutlineLogout size={24} />
          <h1 className='ml-2 font-bold text-lg'>Logout</h1>
        </div>

       
      </div>
    </div>
  )
}

export default LeftSidebar;
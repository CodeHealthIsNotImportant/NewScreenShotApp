import React, { useEffect } from 'react';
import LeftSidebar from './LeftSidebar';
import Content from './Content';
import { useSelector } from 'react-redux';
import { useNavigate } from 'react-router-dom';

const Home = () => {
  const { user } = useSelector(store => store.user);
  const navigate = useNavigate();

  useEffect(() => {
    if (!user) navigate("/login");
  }, [user, navigate]);

  return (
    <div className="flex w-full h-screen">
      {/* Left Sidebar */}
      <div className="w-1/5 border-r border-gray-200 h-full">
        <LeftSidebar />
      </div>

      {/* Content Area */}
      <div className="flex-1 h-full overflow-auto p-4">
        <Content />
      </div>
    </div>
  );
};

export default Home;

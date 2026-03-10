import { createSlice } from "@reduxjs/toolkit";

const userSlice = createSlice({
  name: "user",
  initialState: {
    user: null,
    profile: null, // Added so getMyProfile won't fail
  },
  reducers: {
    // Set the logged-in user
    getUser: (state, action) => {
      state.user = action.payload;
    },
    // Set the user's profile (optional)
    getMyProfile: (state, action) => {
      state.profile = action.payload;
    },
    // Clear user on logout
    clearUser: (state) => {
      state.user = null;
      state.profile = null;
    },
  },
});

export const { getUser, getMyProfile, clearUser } = userSlice.actions;
export default userSlice.reducer;

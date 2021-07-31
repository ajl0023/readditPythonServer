import React, { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { Redirect, Route, Switch } from "react-router-dom";
import { nextPage } from "./actions/postActions";
import { clearLoginModal, loggedIn } from "./actions/userActions";
import Home from "./components/Home";
import Login from "./components/Login";
import Navbar from "./components/Navbar";
import NewPost from "./components/NewPost";
import PostModal from "./components/PostModal";
import Signup from "./components/Signup";
import "./styles/myApp.scss";

function App(props) {
  const [showLogin, setLogin] = useState(false);
  const [darkMode, setDarkMode] = useState(false);
  const [fetchingLogin, setFetchingLogin] = useState(true);
  const [showSignup, setShowSignup] = useState(false);
  const loggedInStatus = useSelector((state) => state.currentUser.isLoggedIn);
  const signedUpStatus = useSelector((state) => state.signup.isSignedUp);
  const dispatch = useDispatch();
  const checkDisplay = useSelector((state) => {
    return state.display.display;
  });
  useEffect(() => {
    dispatch(loggedIn()).then((data) => {
      if (data) {
        setFetchingLogin(false);
      }
    });
  }, [dispatch]);
  useEffect(() => {
    if (loggedInStatus) {
      setLogin(false);
    }
    if (signedUpStatus && !loggedInStatus) {
      setShowSignup(false);
      setLogin(true);
    }
  }, [loggedInStatus, signedUpStatus]);
  const handleShowLogin = () => {
    setLogin(!showLogin);
  };
  const handleShowSignup = () => {
    setShowSignup(!showSignup);
  };
  const closeModal = () => {
    dispatch(clearLoginModal());
    setLogin(false);
    setShowSignup(false);
  };
  const handleShowNextPage = (lastId, sort) => {
    dispatch(nextPage(lastId, sort));
  };

  return (
    <div
      id="scroll-wrapper"
      className={`app-wrapper ${checkDisplay === "dark" ? "dark-mode" : ""}`}
    >
      {showLogin ? <Login close={closeModal} /> : null}
      {showSignup ? <Signup close={closeModal} /> : null}
      <Navbar
        handleShowLogin={handleShowLogin}
        handleShowSignup={handleShowSignup}
      />
      <Route
        exact
        path="/post/:id"
        render={(props) => {
          return (
            <PostModal
              handleShowLogin={handleShowLogin}
              handleShowSignup={handleShowSignup}
              {...props}
            />
          );
        }}
      />
      <Switch>
        <Route
          exact
          path="/new-post"
          render={(props) => {
            return <NewPost {...props} />;
          }}
        >
          {!fetchingLogin && !loggedInStatus ? <Redirect to="/" /> : null}
        </Route>
        <Route
          path={["/:sort", "/"]}
          render={(props2) => {
            return (
              <Home
                handleShowLogin={handleShowLogin}
                handleShowSignup={handleShowSignup}
                handleShowNextPage={handleShowNextPage}
                {...props2}
                test={props.posts}
              />
            );
          }}
          showLogin={showLogin}
          showSignup={showSignup}
        />
      </Switch>
    </div>
  );
}
export default App;

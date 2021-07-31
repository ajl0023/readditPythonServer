import React, { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { Redirect } from "react-router-dom";
import { signup, signupRequest } from "../actions/userActions";
import { CLEAR_ERROR } from "../types";
import Login from "./Login";
const Signup = (props) => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [passwordConfirm, setPasswordConfirm] = useState("");
  const checkDisplay = useSelector((state) => {
    return state.display.display;
  });
  const dispatch = useDispatch();
  const user = useSelector((state) => {
    return state.login.isLoggedIn;
  });
  const error = useSelector((state) => {
    return state.signup.err;
  });
  const passwordError = useSelector((state) => {
    return state.signup.passwordError;
  });
  const handleSignup = () => {
    dispatch(signup(username, password, passwordConfirm)).then((res) => {
      if (res === "signup") {
        <Redirect to={Login}></Redirect>;
      }
    });
  };
  const handleError = () => {
    dispatch({ type: CLEAR_ERROR });
  };
  if (user) {
    window.location.reload();
  }
  useEffect(() => {
    dispatch(signupRequest());
  }, [dispatch]);
  return (
    <div className="login-modal-wrapper">
      <div
        className={`login-card-modal ${
          checkDisplay === "dark" ? "dark-mode-border" : ""
        }`}
      >
        <div className="login-modal-title-exit-container">
          <p
            className={`login-modal-title ${
              checkDisplay === "dark" ? "dark-mode-font" : ""
            }`}
          >
            Sign up
          </p>
          <button
            onClick={props.close}
            className={`login-cancel-button ${
              checkDisplay === "dark" ? "dark-mode-font" : ""
            }`}
          >
            X
          </button>
        </div>
        <div className="login-input-container">
          <input
            onChange={(e) => {
              setUsername(e.target.value);
            }}
            onClick={handleError}
            className={`login-input ${
              checkDisplay === "dark" ? "dark-mode-input" : ""
            }`}
            placeholder="username"
            type="text"
          />
          <p className={`signup-error`}>{error}</p>
          <input
            onChange={(e) => {
              setPassword(e.target.value);
            }}
            className={`login-input ${
              checkDisplay === "dark" ? "dark-mode-input" : ""
            }`}
            placeholder="password"
            type="password"
          />
          <p className={`signup-error`}>{passwordError}</p>
          <input
            onChange={(e) => {
              setPasswordConfirm(e.target.value);
            }}
            className={`login-input ${
              checkDisplay === "dark" ? "dark-mode-input" : ""
            }`}
            placeholder="Confirm your password"
            type="password"
          />
          <button onClick={handleSignup} className="login-button">
            Sign up
          </button>
        </div>
      </div>
    </div>
  );
};
export default Signup;

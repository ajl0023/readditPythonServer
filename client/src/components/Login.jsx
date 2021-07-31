import React, { useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { login } from "../actions/userActions";
const Login = (props) => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const dispatch = useDispatch();
  const checkDisplay = useSelector((state) => {
    return state.display.display;
  });
  const user = useSelector((state) => {
    return state.login.isLoggedIn;
  });
  const error = useSelector((state) => {
    return state.login.err;
  });
  const handleLogin = (e) => {
    if (e.key === "Enter" || e.type === "click") {
      dispatch(login(username, password)).then((x) => {
        if (x === "login") {
          window.location.reload();
        }
      });
    }
  };
  if (user) {
  }
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
            Login
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
            className={`login-input ${
              checkDisplay === "dark" ? "dark-mode-input" : ""
            }`}
            placeholder="username"
            type="text"
          />
          <input
            onKeyDown={handleLogin}
            onChange={(e) => {
              setPassword(e.target.value);
            }}
            className={`login-input ${
              checkDisplay === "dark" ? "dark-mode-input" : ""
            }`}
            placeholder="password"
            type="password"
          />{" "}
          <p className={`signup-error`}>{error}</p>
          <button onClick={handleLogin} className="login-button">
            Log in
          </button>
        </div>
      </div>
    </div>
  );
};
export default Login;

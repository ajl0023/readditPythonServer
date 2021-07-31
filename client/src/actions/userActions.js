import axios from "axios";
import {
  CLEAR_LOGIN_MODAL,
  CURRENT_USER,
  LOGIN_REQUEST,
  LOGIN_SUCCESS,
  REQUEST_USER_INFO,
  SIGNUP_ERROR,
  SIGNUP_REQUEST,
  SIGNUP_SUCCESS,
  UNAUTHORIZED_ERROR,
} from "../types";
let retryCount = 0;
axios.interceptors.request.use((config) => {
  const accessToken = localStorage.getItem("accessToken");
  if (accessToken) {
    config.headers["Authorization"] = `Bearer ${accessToken}`;
  }
  return config;
});
axios.interceptors.response.use(
  function (response) {
    return response;
  },
  function (err) {
    const originalRequest = err.config;
    if (
      (err.response.status === 401 || err.response.status === 403) &&
      !originalRequest._retry &&
      retryCount <= 2 &&
      err.config.url !== "/api/refresh"
    ) {
      retryCount = retryCount + 1;
      originalRequest._retry = true;
      axios({
        url: "/api/refresh",
        method: "POST",
        withCredentials: true,
      }).then((data) => {
        if (data.data) {
          localStorage.setItem("accessToken", data.data.jwt_token);
          axios.defaults.headers.common["Authorization"] =
            "Bearer " + data.jwt_token;
          originalRequest.headers["Authorization"] =
            "Bearer " + data.data.jwt_token;
          return axios(originalRequest);
        }
      });
    } else {
      return Promise.reject(err);
    }
  }
);
function loginRequest() {
  return {
    type: LOGIN_REQUEST,
  };
}
function loginSuccess(username, id) {
  return (dispatch) => {
    dispatch({
      type: LOGIN_SUCCESS,
      username,
      id,
    });
    Promise.resolve("success");
  };
}
export function logOut() {
  return (dispatch) => {
    return axios({
      url: "/api/logout",
      withCredentials: true,
      method: "POST",
    }).then((res) => {
      if (res.status === 200) {
        localStorage.removeItem("accessToken");
        return res;
      }
    });
  };
}
function unauthorized() {
  return {
    type: UNAUTHORIZED_ERROR,
  };
}
export function login(username, password) {
  return (dispatch) => {
    dispatch(loginRequest());
    return axios({
      withCredentials: true,
      method: "POST",
      data: {
        username: username,
        password: password,
      },
      url: "/api/login",
    })
      .then((res) => {
        if (res.status === 200) {
          dispatch(loginSuccess(res.data.username, res.data.id));
          let token = res.data.jwt_token;
          return token;
        }
      })
      .then((token) => {
        localStorage.setItem("accessToken", token);
        return "login";
      })
      .catch(() => {
        dispatch(unauthorized());
      });
  };
}
export function clearLoginModal() {
  return {
    type: CLEAR_LOGIN_MODAL,
  };
}
export function loggedIn() {
  const token = localStorage.getItem("accessToken");
  return async (dispatch) => {
    if (!token) {
      return "completed";
    }
    dispatch({ type: REQUEST_USER_INFO });
    const data = await axios({
      withCredentials: true,
      method: "GET",
      url: "/api/me",
    });
    try {
      dispatch({
        type: CURRENT_USER,
        username: data.data.username,
        user: data.data.id,
      });
      return "completed";
    } catch (error) {
      dispatch(logOut());
    }
  };
}
export function signupRequest() {
  return {
    type: SIGNUP_REQUEST,
  };
}
function signupSuccess() {
  return {
    type: SIGNUP_SUCCESS,
  };
}
export function signup(username, password, passwordConfirm) {
  return (dispatch) => {
    dispatch({ type: SIGNUP_REQUEST });
    return axios({
      url: "/api/signup",
      data: {
        username,
        password,
        passwordConfirm,
      },
      method: "POST",
    })
      .then((res) => {
        if (res.status === 200) {
          dispatch(signupSuccess());
          return "signup";
        }
      })
      .catch((err) => {
        let error = err.response.data;
        let passwordError;
        if (password !== passwordConfirm) {
          passwordError = "Passwords do not match";
        }
        dispatch({ type: SIGNUP_ERROR, error, passwordError });
      });
  };
}

import { applyMiddleware, createStore } from "redux";
import { composeWithDevTools } from "redux-devtools-extension";
import thunkMiddleware from "redux-thunk";
import { loadState } from "../localStorage";
import rootReducer from "../reducers/reducer";
export default function configureStore(preloadedState) {
  const persistedState = loadState();
  const composeEnhancers = composeWithDevTools({ trace: true });
  return createStore(
    rootReducer,
    persistedState,
    composeEnhancers(applyMiddleware(thunkMiddleware))
  );
}

import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { MantineProvider } from '@mantine/core';
import '@mantine/core/styles.css';
import App from './App';
import { mantineTheme } from './theme/mantineTheme';
import './index.css';
const routerBase = (import.meta.env.BASE_URL || '/console/').replace(/\/$/, '');
ReactDOM.createRoot(document.getElementById('root')).render(<React.StrictMode>
    <BrowserRouter basename={routerBase}>
      <MantineProvider theme={mantineTheme} defaultColorScheme="dark">
        <App />
      </MantineProvider>
    </BrowserRouter>
  </React.StrictMode>);

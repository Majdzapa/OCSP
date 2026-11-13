import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { MantineProvider } from '@mantine/core'
import '@mantine/core/styles.css'
import App from './App'
import { mantineTheme } from './theme/mantineTheme'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <MantineProvider theme={mantineTheme} defaultColorScheme="dark">
        <App />
      </MantineProvider>
    </BrowserRouter>
  </React.StrictMode>
)

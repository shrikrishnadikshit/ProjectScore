import React from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Route, Routes } from 'react-router-dom'
import Layout from './components/Layout.jsx'
import Portfolio from './pages/Portfolio.jsx'
import EntityDetail from './pages/EntityDetail.jsx'
import Team from './pages/Team.jsx'
import Account from './pages/Account.jsx'
import Scanner from './pages/Scanner.jsx'
import OptOuts from './pages/OptOuts.jsx'
import DeepScans from './pages/DeepScans.jsx'
import './styles.css'

createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/scanner" element={<Scanner />} />
        <Route element={<Layout />}>
          <Route path="/" element={<Portfolio />} />
          <Route path="/entities/:id" element={<EntityDetail />} />
          <Route path="/team" element={<Team />} />
          <Route path="/account" element={<Account />} />
          <Route path="/opt-outs" element={<OptOuts />} />
          <Route path="/in-depth" element={<DeepScans />} />
          <Route path="/in-depth/:scanId" element={<DeepScans />} />
        </Route>
      </Routes>
    </BrowserRouter>
  </React.StrictMode>,
)

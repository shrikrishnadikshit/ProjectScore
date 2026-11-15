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
import Disputes from './pages/Disputes.jsx'
import FreeReport from './pages/FreeReport.jsx'
import Leads from './pages/Leads.jsx'
import Alerts from './pages/Alerts.jsx'
import QuestionnaireView from './pages/QuestionnaireView.jsx'
import VendorQuestionnaire from './pages/VendorQuestionnaire.jsx'
import './styles.css'

createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/scanner" element={<Scanner />} />
        <Route path="/free-report" element={<FreeReport />} />
        <Route path="/q/:token" element={<VendorQuestionnaire />} />
        <Route element={<Layout />}>
          <Route path="/" element={<Portfolio />} />
          <Route path="/entities/:id" element={<EntityDetail />} />
          <Route path="/team" element={<Team />} />
          <Route path="/account" element={<Account />} />
          <Route path="/opt-outs" element={<OptOuts />} />
          <Route path="/disputes" element={<Disputes />} />
          <Route path="/leads" element={<Leads />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/questionnaires/:id" element={<QuestionnaireView />} />
          <Route path="/in-depth" element={<DeepScans />} />
          <Route path="/in-depth/:scanId" element={<DeepScans />} />
        </Route>
      </Routes>
    </BrowserRouter>
  </React.StrictMode>,
)

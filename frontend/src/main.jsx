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
import Advisory from './pages/Advisory.jsx'
import CodeReviews from './pages/CodeReviews.jsx'
import FourthParties from './pages/FourthParties.jsx'
import VendorFix from './pages/VendorFix.jsx'
import Threats from './pages/Threats.jsx'
import Policy from './pages/Policy.jsx'
import Settings from './pages/Settings.jsx'
import Methodology from './pages/Methodology.jsx'
import Legal from './pages/Legal.jsx'
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
        <Route path="/v/:token" element={<VendorFix />} />
        <Route path="/methodology" element={<Methodology />} />
        <Route path="/terms" element={<Legal />} />
        <Route path="/privacy" element={<Legal />} />
        <Route path="/dpa" element={<Legal />} />
        <Route element={<Layout />}>
          <Route path="/" element={<Portfolio />} />
          <Route path="/entities/:id" element={<EntityDetail />} />
          <Route path="/team" element={<Team />} />
          <Route path="/account" element={<Account />} />
          <Route path="/opt-outs" element={<OptOuts />} />
          <Route path="/disputes" element={<Disputes />} />
          <Route path="/leads" element={<Leads />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/advisory" element={<Advisory />} />
          <Route path="/code-reviews" element={<CodeReviews />} />
          <Route path="/supply-chain" element={<FourthParties />} />
          <Route path="/threats" element={<Threats />} />
          <Route path="/policy" element={<Policy />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/code-reviews/:reviewId" element={<CodeReviews />} />
          <Route path="/questionnaires/:id" element={<QuestionnaireView />} />
          <Route path="/in-depth" element={<DeepScans />} />
          <Route path="/in-depth/:scanId" element={<DeepScans />} />
        </Route>
      </Routes>
    </BrowserRouter>
  </React.StrictMode>,
)

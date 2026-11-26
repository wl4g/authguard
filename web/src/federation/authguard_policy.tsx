import * as authguard_boundary from './authguard_boundary'
import * as authguard_frame from './authguard_page_frame'
import * as authguard_page from '../dashboard/PolicyPage'

export default function authguard_policy(authguard_props: authguard_boundary.authguard_remote_props) {
  return <authguard_boundary.authguard_boundary {...authguard_props}><authguard_frame.authguard_page_frame authguard_on_return={authguard_props.authguard_on_return}><authguard_page.PolicyPage/></authguard_frame.authguard_page_frame></authguard_boundary.authguard_boundary>
}

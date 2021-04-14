import {Splash} from '../screens/setup/sub-components/Splash';
import {DETAILS_SCREENS} from '../screens/details';
import {CREATE_SCREENS} from '../screens/create';
import {EDIT_SCREENS} from '../screens/edit';

const DETAILS_SCREEN_PREFIX = 'details/';
const CREATE_SCREEN_PREFIX = 'create/';
const POST_CREATE_SCREENS_PREFIX = 'post-create/';
const SETUP_SCREEN_PREFIX = 'setup/';
const EDIT_SCREEN_PREFIX = 'edit/';
const CONFIGURATION_SCREEN_PREFIX = 'configuration/';
const POST_CONFIGURATION_SCREEN_PREFIX = 'post-config/';
const SP = SETUP_SCREEN_PREFIX;
const DP = DETAILS_SCREEN_PREFIX;
const EP = EDIT_SCREEN_PREFIX;
const CP = CREATE_SCREEN_PREFIX;

const SCREEN_TYPES = {
    [`${DP}image`]: DETAILS_SCREENS.ImageDetailScreen,
};

export {SCREEN_TYPES, DETAILS_SCREEN_PREFIX, CREATE_SCREEN_PREFIX, POST_CREATE_SCREENS_PREFIX, EDIT_SCREEN_PREFIX, SETUP_SCREEN_PREFIX, CONFIGURATION_SCREEN_PREFIX, POST_CONFIGURATION_SCREEN_PREFIX};

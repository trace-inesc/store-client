/*
 * Copyright (c) 2016 Rodrigo Lourenço, Miguel Costa, Paulo Ferreira, João Barreto @  INESC-ID.
 *
 * This file is part of TRACE.
 *
 * TRACE is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * TRACE is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with TRACE.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.trace.storeclient;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;


/**
 * <emph>Note:</emph> Soon to be deprecated. Avoid its use.
 */
public class TRACEStoreReceiver extends BroadcastReceiver {

    public TRACEStoreReceiver(){}

    @Override
    public void onReceive(Context context, Intent intent) {


        if(intent.hasExtra(StoreClientConstants.FIRST_TIME_BROADCAST)
                && intent.getBooleanExtra(StoreClientConstants.FIRST_TIME_BROADCAST, true)){

            /**
             * TODO: send and action that means that a login activity should be presented.
            context.startActivity(
                    new Intent(context, LoginActivity.class)
                    .setFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
             **/

            return;
        }

    }
}

/*
 * Copyright (C) 2021 Evtech Solutions, Ltd., dba 3D-P
 * Copyright (C) 2021 Neil Tallim <neiltallim@3d-p.com>
 *
 * This file is part of rperf.
 *
 * rperf is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * rperf is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with rperf.  If not, see <https://www.gnu.org/licenses/>.
 */

pub mod ktls;
pub mod tcp;
pub mod tls;
pub mod udp;

use std::error::Error;

type BoxResult<T> = Result<T, Box<dyn Error>>;

pub const INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

fn parse_port_spec(port_spec: String) -> Vec<u16> {
    let mut ports = Vec::<u16>::new();
    if !port_spec.is_empty() {
        for range in port_spec.split(',') {
            if range.contains('-') {
                let mut range_spec = range.split('-');
                let range_first = range_spec.next().unwrap().parse::<u16>().unwrap();
                let range_last = range_spec.last().unwrap().parse::<u16>().unwrap();

                for port in range_first..=range_last {
                    ports.push(port);
                }
            } else {
                ports.push(range.parse::<u16>().unwrap());
            }
        }

        ports.sort();
    }

    return ports;
}

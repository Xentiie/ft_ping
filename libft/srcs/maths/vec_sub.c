/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   vec_sub.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/25 18:10:46 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/10 21:52:37 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#include "libft/maths.h"

t_v2 vec2_sub(t_v2 a, t_v2 b) { return vec2(a.x - b.x, a.y - b.y); }
t_v3 vec3_sub(t_v3 a, t_v3 b) { return vec3(a.x - b.x, a.y - b.y, a.z - b.z); }
t_v4 vec4_sub(t_v4 a, t_v4 b) { return vec4(a.x - b.x, a.y - b.y, a.z - b.z, a.w - b.w); }
t_iv2 ivec2_sub(t_iv2 a, t_iv2 b) { return ivec2(a.x - b.x, a.y - b.y); }
t_iv3 ivec3_sub(t_iv3 a, t_iv3 b) { return ivec3(a.x - b.x, a.y - b.y, a.z - b.z); }
t_iv4 ivec4_sub(t_iv4 a, t_iv4 b) { return ivec4(a.x - b.x, a.y - b.y, a.z - b.z, a.w - b.w); }
